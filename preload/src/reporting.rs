//! The in-guest refusal reporter: a Tool that delegates every callback to
//! literoot's shared `RootfsTool` unchanged and reports, over the
//! coordinator RPC, each refusal the in-guest runtime or host made, so the
//! launcher writes it to its side log (`--refusal-log`).
//!
//! It drains at entry to every guest callback and in `on_exit_thread` and
//! `on_exit_process`:
//! - the runtime's records of refused signal handlers and alternate stacks,
//!   and of refused fork-like calls (taking clears them);
//! - the refusals the shared Tool itself made in this process.
//!
//! After the delegated `handle_syscall_event` returns it takes the host's
//! unsupported-operation refusal for that dispatch, which the next
//! dispatch would clear. `RootfsTool` overrides `new`, `subscriptions`,
//! `init_thread_state`, `handle_thread_start`, `handle_post_exec`,
//! `handle_syscall_event` and `on_exit_process`; every other method keeps
//! the trait default here, as it does there.

use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Signal;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::UnsupportedOperation;
use reverie::syscalls::Syscall;
#[cfg(feature = "inguest-trap")]
use reverie_inguest::guest::protect as records;
#[cfg(not(feature = "inguest-trap"))]
use reverie_liteinst as records;

use crate::rootfs_tool::ForkKind;
use crate::rootfs_tool::LiterootConfig;
use crate::rootfs_tool::LiterootGlobal;
use crate::rootfs_tool::Refusal;
use crate::rootfs_tool::Refused;
use crate::rootfs_tool::RootfsThreadState;
use crate::rootfs_tool::RootfsTool;
use crate::rootfs_tool::UnsupportedKind;

/// `RootfsTool`, reporting its process's refusals.
#[derive(Debug, Default)]
pub struct ReportingTool {
    inner: RootfsTool,
}

impl ReportingTool {
    /// Report the refusals of `inner`'s process (a Tool rebuilt from a
    /// predecessor's snapshot).
    #[cfg(feature = "successor")]
    pub fn wrapping(inner: RootfsTool) -> Self {
        Self { inner }
    }
}

impl AsMut<RootfsTool> for ReportingTool {
    fn as_mut(&mut self) -> &mut RootfsTool {
        &mut self.inner
    }
}

/// The refusals recorded in this process since the last drain.
fn drained() -> Vec<Refusal> {
    let mut found = Vec::new();
    let signals = records::take_refused_signal_controls();
    for n in 1..=64u8 {
        if signals.actions & (1 << (n - 1)) != 0 {
            found.push(Refusal::SignalAction(n));
        }
    }
    if signals.alternate_stack {
        found.push(Refusal::AlternateStack);
    }
    let forks = records::take_refused_process_creations();
    for (refused, kind) in [
        (forks.clone_thread, ForkKind::CloneThread),
        (forks.clone_process, ForkKind::CloneProcess),
        (forks.clone3, ForkKind::Clone3),
        (forks.fork, ForkKind::Fork),
        (forks.vfork, ForkKind::Vfork),
    ] {
        if refused {
            found.push(Refusal::ForkPolicy(kind));
        }
    }
    let tool =
        crate::rootfs_tool::PENDING_GUEST_REFUSALS.swap(0, std::sync::atomic::Ordering::AcqRel);
    for (i, &kind) in crate::rootfs_tool::GUEST_KINDS.iter().enumerate() {
        if tool & (1 << i) != 0 {
            found.push(Refusal::Guest(kind));
        }
    }
    found
}

/// Send `refusals` to the launcher, which writes them before it answers.
/// An empty drain sends nothing.
async fn report<G: GlobalRPC<LiterootGlobal> + ?Sized>(rpc: &G, refusals: Vec<Refusal>) {
    if !refusals.is_empty() {
        rpc.send_rpc(Refused(refusals)).await;
    }
}

/// The side-log refusal for a host refusal of one dispatch.
fn unsupported(operation: UnsupportedOperation) -> Refusal {
    use UnsupportedKind as K;
    use UnsupportedOperation as O;
    match operation {
        O::Exec => Refusal::Exec,
        O::NativeExec => Refusal::Unsupported(K::NativeExec),
        O::ThreadCreation => Refusal::Unsupported(K::ThreadCreation),
        _ => Refusal::Unsupported(K::Other),
    }
}

#[reverie::tool]
impl Tool for ReportingTool {
    type GlobalState = LiterootGlobal;
    type ThreadState = RootfsThreadState;

    fn new(pid: Pid, cfg: &<LiterootGlobal as GlobalTool>::Config) -> Self {
        Self {
            inner: RootfsTool::new(pid, cfg),
        }
    }

    fn subscriptions(cfg: &LiterootConfig) -> Subscription {
        RootfsTool::subscriptions(cfg)
    }

    fn init_thread_state(
        &self,
        child: Tid,
        parent: Option<(Tid, &RootfsThreadState)>,
    ) -> RootfsThreadState {
        self.inner.init_thread_state(child, parent)
    }

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        report(&*guest, drained()).await;
        self.inner
            .handle_thread_start(&mut guest.into_guest())
            .await
    }

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        report(&*guest, drained()).await;
        self.inner.handle_post_exec(&mut guest.into_guest()).await
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        report(&*guest, drained()).await;
        let result = self
            .inner
            .handle_syscall_event(&mut guest.into_guest(), syscall)
            .await;
        // The host's refusal of this dispatch, taken before anything else
        // is injected (the next dispatch would clear it).
        if let Some(refusal) = guest.take_unsupported_refusal() {
            report(&*guest, vec![unsupported(refusal.operation)]).await;
        }
        result
    }

    async fn handle_cpuid_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        eax: u32,
        ecx: u32,
    ) -> Result<reverie::CpuIdResult, Errno> {
        report(&*guest, drained()).await;
        self.inner
            .handle_cpuid_event(&mut guest.into_guest(), eax, ecx)
            .await
    }

    async fn handle_rdtsc_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        report(&*guest, drained()).await;
        self.inner
            .handle_rdtsc_event(&mut guest.into_guest(), request)
            .await
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        report(&*guest, drained()).await;
        self.inner
            .handle_signal_event(&mut guest.into_guest(), signal)
            .await
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        report(&*guest, drained()).await;
        self.inner.handle_timer_event(&mut guest.into_guest()).await
    }

    async fn on_exit_thread<G: GlobalRPC<LiterootGlobal>>(
        &self,
        tid: Tid,
        global_state: &G,
        thread_state: RootfsThreadState,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        report(global_state, drained()).await;
        self.inner
            .on_exit_thread(tid, global_state, thread_state, exit_status)
            .await
    }

    async fn on_exit_process<G: GlobalRPC<LiterootGlobal>>(
        self,
        pid: Pid,
        global_state: &G,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        report(global_state, drained()).await;
        self.inner
            .on_exit_process(pid, global_state, exit_status)
            .await
    }
}
