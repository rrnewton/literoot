//! The literoot initial-image packet (`LRIINIT1`) and the admission of a
//! mapped first image (design: row d addendum, revision 3).
//!
//! The launcher writes this packet into the first image's table 3; the
//! image's initializer decodes it, checks this build's config wire
//! fingerprint, connects to the coordinator it names, moves that
//! connection to the runtime's descriptor numbers, and redeems an
//! InitialImage client with the packet's nonce and expected Config digest.
//! The packet is a launcher-written description, not authority: the
//! coordinator's one-use redemption against the watched birth is.
//!
//! Shared by `#[path]`: the root crate compiles it (with
//! `private-runtime` and `tool`) for the launcher side and its host tests,
//! and the preload compiles it into the musl mapped image.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd as _;
use std::os::fd::FromRawFd as _;
use std::os::fd::IntoRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::InitialImageClient;
use reverie_rpc_transport::RpcError;
use reverie_rpc_transport::codec;
use sha2::Digest as _;
use sha2::Sha256;

use crate::rootfs_tool::ForkKind;
use crate::rootfs_tool::GuestKind;
use crate::rootfs_tool::LiterootConfig;
use crate::rootfs_tool::LiterootGlobal;
use crate::rootfs_tool::Refusal;
use crate::rootfs_tool::Refused;
use crate::rootfs_tool::UnsupportedKind;

/// The packet's magic.
pub const MAGIC: [u8; 8] = *b"LRIINIT1";
/// The only version accepted; a future layout gets a new version and a
/// separate decoder.
pub const VERSION: u16 = 1;
/// The fixed header before the coordinator path.
pub const HEADER_LEN: usize = 94;
/// Rust std's pathname bound for `SocketAddr::from_pathname` (it refuses
/// 108 bytes or more); not a kernel limit.
pub const MAX_PATH_LEN: usize = 107;
/// `HEADER_LEN + MAX_PATH_LEN`. Reverie's packet lease bound is 4096.
pub const MAX_PACKET_LEN: usize = HEADER_LEN + MAX_PATH_LEN;
/// The redemption nonce's fixed size.
pub const NONCE_LEN: usize = 32;
/// Lowercase hex characters of the config wire fingerprint.
pub const FINGERPRINT_LEN: usize = 16;

const NONCE_AT: usize = 12;
const DIGEST_AT: usize = 44;
const FINGERPRINT_AT: usize = 76;
const PATH_LEN_AT: usize = 92;

/// A decoded packet, borrowing the bytes it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub nonce: &'a [u8; NONCE_LEN],
    pub config_digest: &'a [u8; 32],
    pub fingerprint: &'a [u8; FINGERPRINT_LEN],
    pub coordinator: &'a [u8],
}

/// The format refusals of [`decode`], in its check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// D1 (`94 <= len <= 201`) or D4 (the total field equals the length).
    Size,
    /// D2.
    Magic,
    /// D3.
    Version,
    /// D5: the path length does not consume the packet exactly.
    Length,
    /// D6: the path is not absolute, is shorter than 2 bytes, or has a NUL.
    Path,
    /// D7: the fingerprint field is not 16 lowercase hex characters.
    Fingerprint,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecodeError::Size => "literoot initial packet: size",
            DecodeError::Magic => "literoot initial packet: magic",
            DecodeError::Version => "literoot initial packet: version",
            DecodeError::Length => "literoot initial packet: coordinator length",
            DecodeError::Path => "literoot initial packet: coordinator path",
            DecodeError::Fingerprint => "literoot initial packet: fingerprint format",
        })
    }
}

/// The refusals of [`encode`].
// The launcher's side (rows e/f): the preload's image decodes and never
// encodes, so this and `encode` are its only unused items.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// E1: the path is not 2 to 107 bytes.
    PathLength,
    /// E2: the path is not absolute, or has a NUL.
    Path,
    /// E3: the fingerprint is not 16 lowercase hex characters.
    Fingerprint,
}

fn be16(bytes: &[u8], at: usize) -> Option<usize> {
    let field = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([field[0], field[1]]) as usize)
}

fn is_lower_hex(field: &[u8]) -> bool {
    field
        .iter()
        .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn path_ok(path: &[u8]) -> bool {
    path.len() >= 2 && path[0] == b'/' && !path.contains(&0)
}

/// Decodes a packet. Checks in a total order (D1-D7) and stops at the first
/// failure; reads only after the check that guards the read.
pub fn decode(bytes: &[u8]) -> Result<Packet<'_>, DecodeError> {
    let len = bytes.len();
    // D1
    if !(HEADER_LEN..=MAX_PACKET_LEN).contains(&len) {
        return Err(DecodeError::Size);
    }
    // D2
    if bytes[..8] != MAGIC {
        return Err(DecodeError::Magic);
    }
    // D3
    if be16(bytes, 8) != Some(VERSION as usize) {
        return Err(DecodeError::Version);
    }
    // D4
    if be16(bytes, 10) != Some(len) {
        return Err(DecodeError::Size);
    }
    // D5
    let n = be16(bytes, PATH_LEN_AT).ok_or(DecodeError::Length)?;
    if HEADER_LEN + n != len {
        return Err(DecodeError::Length);
    }
    // D6. n <= 107 follows from D1 and D5.
    let coordinator = &bytes[HEADER_LEN..];
    if !path_ok(coordinator) {
        return Err(DecodeError::Path);
    }
    // D7
    let fingerprint: &[u8; FINGERPRINT_LEN] = bytes[FINGERPRINT_AT..PATH_LEN_AT]
        .try_into()
        .map_err(|_| DecodeError::Fingerprint)?;
    if !is_lower_hex(fingerprint) {
        return Err(DecodeError::Fingerprint);
    }
    Ok(Packet {
        nonce: bytes[NONCE_AT..DIGEST_AT]
            .try_into()
            .map_err(|_| DecodeError::Size)?,
        config_digest: bytes[DIGEST_AT..FINGERPRINT_AT]
            .try_into()
            .map_err(|_| DecodeError::Size)?,
        fingerprint,
        coordinator,
    })
}

/// Encodes a packet (the launcher's side). Refuses exactly what [`decode`]
/// would refuse (E1-E3), so it never emits a packet the image refuses.
#[allow(dead_code)] // No caller in the preload's image; see `EncodeError`.
pub fn encode(
    nonce: &[u8; NONCE_LEN],
    config_digest: &[u8; 32],
    fingerprint: &[u8; FINGERPRINT_LEN],
    coordinator: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    // E1
    if !(2..=MAX_PATH_LEN).contains(&coordinator.len()) {
        return Err(EncodeError::PathLength);
    }
    // E2
    if !path_ok(coordinator) {
        return Err(EncodeError::Path);
    }
    // E3
    if !is_lower_hex(fingerprint) {
        return Err(EncodeError::Fingerprint);
    }
    let total = HEADER_LEN + coordinator.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(config_digest);
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(&(coordinator.len() as u16).to_be_bytes());
    out.extend_from_slice(coordinator);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Config wire fingerprint
// ---------------------------------------------------------------------------

/// Bumped with any change to `Refusal` or its nested kinds, as Detcore's
/// `GLOBAL_RPC_REVISION` is; the refusal-wire domain catches what a missed
/// bump would not.
pub const REFUSAL_RPC_REVISION: u32 = 1;

const TAG_CONFIG_WIRE: &[u8] = b"literoot.config.wire.v1";
const TAG_CONFIG_JSON: &[u8] = b"literoot.config.json.v1";
const TAG_REFUSAL_REVISION: &[u8] = b"literoot.refusal.rpc.revision";
const TAG_REFUSAL_WIRE: &[u8] = b"literoot.refusal.rpc.wire.v1";

/// One exhaustive `LiterootConfig` value, with no `..Default::default()`, so
/// a new field does not compile until it is set here. Every `Option` is
/// `Some`, every `Vec` non-empty, and same-typed fields have pairwise
/// distinct values. The integers are above their signed maximum, so
/// retyping one of these fields to the signed type of the same width makes
/// its literal a compile error: that retype would otherwise leave both the
/// JSON and the fixed-width bincode bytes unchanged.
pub fn canonical_config() -> LiterootConfig {
    LiterootConfig {
        rootfs: "/literoot/canonical/rootfs".into(),
        binds: vec![("/guest/bind".into(), "/host/bind".into(), true)],
        cwd: "/canonical/cwd".into(),
        fake_root: true,
        fake_uid: Some(0x8000_0001),
        fake_gid: Some(0x8000_0002),
        kernel_release: Some("canonical-release".into()),
        kill_on_exit: true,
        kompat_force: false,
        post_exec_at_exec_stop: true,
        refuse_guest_ptrace: false,
        initial_exe: "/canonical/initial_exe".into(),
        initial_argv: vec!["canonical-argv0".into(), "canonical-argv1".into()],
        initial_stack_limit: Some((0x8000_0000_0000_0003, 0x8000_0000_0000_0004)),
    }
}

/// `serde_json::to_string(&canonical_config())`: every field's name, its
/// position (declaration order) and its JSON value kind. The image does not
/// build JSON; a root-crate host test pins this constant to serde's output.
pub const CONFIG_JSON: &str = concat!(
    r#"{"rootfs":"/literoot/canonical/rootfs","#,
    r#""binds":[["/guest/bind","/host/bind",true]],"#,
    r#""cwd":"/canonical/cwd","#,
    r#""fake_root":true,"#,
    r#""fake_uid":2147483649,"#,
    r#""fake_gid":2147483650,"#,
    r#""kernel_release":"canonical-release","#,
    r#""kill_on_exit":true,"#,
    r#""kompat_force":false,"#,
    r#""post_exec_at_exec_stop":true,"#,
    r#""refuse_guest_ptrace":false,"#,
    r#""initial_exe":"/canonical/initial_exe","#,
    r#""initial_argv":["canonical-argv0","canonical-argv1"],"#,
    r#""initial_stack_limit":[9223372036854775811,9223372036854775812]}"#,
);

/// A distinct tag per `Refusal` value of [`canonical_refusals`]. The match
/// has no `_` arm, so a new variant (or nested kind) does not compile until
/// it is listed here and in [`canonical_refusals`].
fn refusal_tag(refusal: Refusal) -> u8 {
    match refusal {
        Refusal::Exec => 0,
        Refusal::ForkPolicy(ForkKind::CloneThread) => 1,
        Refusal::ForkPolicy(ForkKind::CloneProcess) => 2,
        Refusal::ForkPolicy(ForkKind::Clone3) => 3,
        Refusal::ForkPolicy(ForkKind::Fork) => 4,
        Refusal::ForkPolicy(ForkKind::Vfork) => 5,
        Refusal::SignalAction(_) => 6,
        Refusal::AlternateStack => 7,
        Refusal::Unsupported(UnsupportedKind::NativeExec) => 8,
        Refusal::Unsupported(UnsupportedKind::ThreadCreation) => 9,
        Refusal::Unsupported(UnsupportedKind::Other) => 10,
        Refusal::Guest(GuestKind::Ptrace) => 11,
        Refusal::Guest(GuestKind::SelfStop) => 12,
        Refusal::Guest(GuestKind::SharedRecordPublish) => 13,
        Refusal::Guest(GuestKind::NodenameWrite) => 14,
        Refusal::Guest(GuestKind::DomainnameWrite) => 15,
        Refusal::Guest(GuestKind::KompatAuxv) => 16,
        Refusal::Guest(GuestKind::FakeIdAuxv) => 17,
    }
}

/// One `Refused` request per `Refusal` variant and nested kind, in
/// [`refusal_tag`] order: the request type `LiterootGlobal` sends as
/// positional bincode outside `LiterootConfig`.
pub fn canonical_refusals() -> Vec<Refused> {
    let all = [
        Refusal::Exec,
        Refusal::ForkPolicy(ForkKind::CloneThread),
        Refusal::ForkPolicy(ForkKind::CloneProcess),
        Refusal::ForkPolicy(ForkKind::Clone3),
        Refusal::ForkPolicy(ForkKind::Fork),
        Refusal::ForkPolicy(ForkKind::Vfork),
        Refusal::SignalAction(64),
        Refusal::AlternateStack,
        Refusal::Unsupported(UnsupportedKind::NativeExec),
        Refusal::Unsupported(UnsupportedKind::ThreadCreation),
        Refusal::Unsupported(UnsupportedKind::Other),
        Refusal::Guest(GuestKind::Ptrace),
        Refusal::Guest(GuestKind::SelfStop),
        Refusal::Guest(GuestKind::SharedRecordPublish),
        Refusal::Guest(GuestKind::NodenameWrite),
        Refusal::Guest(GuestKind::DomainnameWrite),
        Refusal::Guest(GuestKind::KompatAuxv),
        Refusal::Guest(GuestKind::FakeIdAuxv),
    ];
    debug_assert!(
        all.iter()
            .enumerate()
            .all(|(i, &r)| refusal_tag(r) as usize == i)
    );
    all.into_iter().map(|r| Refused(vec![r])).collect()
}

/// Truncated SHA-256 over `(tag, payload)` domains, each written as an
/// 8-byte little-endian tag length, the tag, an 8-byte little-endian payload
/// length, then the payload. Takes any domains, so tests call it directly.
pub fn hash_domains(domains: &[(&[u8], &[u8])]) -> [u8; 8] {
    let mut hash = Sha256::new();
    for (tag, payload) in domains {
        hash.update((tag.len() as u64).to_le_bytes());
        hash.update(tag);
        hash.update((payload.len() as u64).to_le_bytes());
        hash.update(payload);
    }
    let digest = hash.finalize();
    let mut out = [0; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Lowercase hex of `bytes`.
pub fn hex16(bytes: [u8; 8]) -> [u8; FINGERPRINT_LEN] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0; FINGERPRINT_LEN];
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = DIGITS[(b >> 4) as usize];
        out[2 * i + 1] = DIGITS[(b & 0xf) as usize];
    }
    out
}

fn encoded<T: serde::Serialize>(value: &T) -> Vec<u8> {
    // Encoding these in-memory values cannot fail: bincode refuses only
    // unsupported types, which a host test would catch at once.
    codec::encode(value).expect("literoot initial packet: canonical value encodes")
}

/// The refusal-wire payload: each canonical `Refused`, length-prefixed.
pub fn refusal_wire() -> Vec<u8> {
    let mut out = Vec::new();
    for refused in canonical_refusals() {
        let bytes = encoded(&refused);
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

/// This build's config wire fingerprint, computed once. It allocates
/// (`codec::encode` returns a `Vec`), so the image calls it after its
/// private libc and allocator are ready.
pub fn literoot_config_wire_fingerprint() -> &'static [u8; FINGERPRINT_LEN] {
    static FINGERPRINT: OnceLock<[u8; FINGERPRINT_LEN]> = OnceLock::new();
    FINGERPRINT.get_or_init(|| {
        let wire = encoded(&canonical_config());
        let revision = REFUSAL_RPC_REVISION.to_le_bytes();
        let refusals = refusal_wire();
        hex16(hash_domains(&[
            (TAG_CONFIG_WIRE, &wire),
            (TAG_CONFIG_JSON, CONFIG_JSON.as_bytes()),
            (TAG_REFUSAL_REVISION, &revision),
            (TAG_REFUSAL_WIRE, &refusals),
        ]))
    })
}

// ---------------------------------------------------------------------------
// Coordinator connection placement
// ---------------------------------------------------------------------------

/// Why the production connector failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    /// `connect` failed; the errno.
    Unreachable(i32),
    /// The connection could not be placed in the runtime's top band. `errno`
    /// is the placement's error, or 0 when it placed the connection lower
    /// (or left it where `connect` put it); `placed` is that number, or -1.
    FdMove { errno: i32, placed: i32 },
}

impl From<ConnectError> for io::Error {
    fn from(error: ConnectError) -> Self {
        match error {
            ConnectError::Unreachable(errno) => io::Error::from_raw_os_error(errno),
            ConnectError::FdMove { errno: 0, placed } => io::Error::other(format!(
                "literoot coordinator connection: no runtime descriptor number free \
                 under the soft RLIMIT_NOFILE (it would sit at {placed})"
            )),
            ConnectError::FdMove { errno, .. } => io::Error::from_raw_os_error(errno),
        }
    }
}

/// The lowest number of the runtime's top band under soft limit `soft`:
/// `RUNTIME_FD_MIN` (1025) where the limit leaves a number there, else the
/// fallback band of the top 8 numbers below the limit (1016 under 1024),
/// as `reverie_inguest::guest::protect::runtime_fd_minimums` places them.
pub fn top_band_floor(soft: u64) -> i32 {
    const RESERVE: u64 = 8;
    let min = reverie_inguest::guest::protect::RUNTIME_FD_MIN as u64;
    if soft >= min + RESERVE {
        min as i32
    } else {
        soft.saturating_sub(RESERVE).clamp(3, min) as i32
    }
}

fn soft_nofile() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid out-pointer for the call's duration.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0).then_some(limit.rlim_cur)
}

/// Moves a fresh coordinator connection to the runtime's descriptor numbers
/// and accepts it only in the top band: at or above 1025, or, under a soft
/// `RLIMIT_NOFILE` that leaves no number there, the 8 numbers just below the
/// limit. A lower block, or no move at all (Reverie leaves the connection
/// where `connect` put it when no number is free), refuses
/// [`ConnectError::FdMove`] and closes the connection. This is stricter
/// than Reverie's ordinary connection, which accepts every block down to 3.
/// If Reverie's placement call itself errors, it returns with a number
/// still open and does not say which (the connect-time number or the moved
/// one), so that number is not closed here; the refusal is terminal for the
/// image either way.
///
/// The placement records nothing. Reverie's installation reserves the
/// coordinator descriptor exactly once, after `from_live_client`
/// (reverie-liteinst `tool_host.rs:1598`, `reserve_coordinator_fd`), and a
/// second reservation is refused there. That is sound because between this
/// placement and that reservation no guest code and no guest signal handler
/// runs: this is a first image or a fresh successor image, the exec reset
/// every handler, no guest instruction has run, and signals stay blocked
/// during the placement itself. Revisit this choice, and record inside the
/// placement instead, if literoot ever runs guest code or unblocks signals
/// between placement and installation.
pub fn place_coordinator_stream(stream: UnixStream) -> Result<UnixStream, ConnectError> {
    let soft = soft_nofile().ok_or(ConnectError::FdMove {
        errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        placed: -1,
    })?;
    let connected = stream.as_raw_fd();
    let placed =
        reverie_inguest::guest::protect::place_runtime_fd_and(stream.into_raw_fd(), |_| Ok(()))
            .map_err(|error| ConnectError::FdMove {
                errno: error.raw_os_error().unwrap_or(0),
                placed: -1,
            })?;
    // SAFETY: `placed` is the connection's only descriptor, owned here.
    let placed_stream = unsafe { UnixStream::from_raw_fd(placed) };
    if placed == connected || placed < top_band_floor(soft) {
        drop(placed_stream);
        return Err(ConnectError::FdMove { errno: 0, placed });
    }
    Ok(placed_stream)
}

/// The production connector: `connect`, then [`place_coordinator_stream`].
/// Used by the mapped first image and by the mapped successor.
pub fn connect_coordinator(path: &Path) -> Result<UnixStream, ConnectError> {
    let stream = UnixStream::connect(path)
        .map_err(|error| ConnectError::Unreachable(error.raw_os_error().unwrap_or(0)))?;
    place_coordinator_stream(stream)
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// The sealed table-4 coordinator carriage, as the initializer read it.
/// Only Reverie's `Err(Absent)` becomes [`Carriage::Absent`]; `Duplicate`,
/// `Empty` and `Format` become [`Carriage::Malformed`] with Reverie's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carriage<'a> {
    Absent,
    Present(&'a [u8]),
    Malformed(&'static str),
}

/// Which digest check the client failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestCheck {
    Ack,
    Config,
}

const ACK_DIGEST_MISMATCH: &str = "InitialImage acknowledgement config digest mismatch";
const CONFIG_DIGEST_MISMATCH: &str = "InitialImage raw config digest mismatch";

/// Admission refusals. Every one is terminal for the image.
#[derive(Debug)]
pub enum AdmitError<'a> {
    Decode(DecodeError),
    FingerprintMismatch {
        packet: [u8; FINGERPRINT_LEN],
        ours: [u8; FINGERPRINT_LEN],
    },
    CoordinatorCarriageDisagrees {
        packet: &'a [u8],
        carriage: &'a [u8],
    },
    CoordinatorCarriageMalformed(&'static str),
    CoordinatorUnreachable {
        path: &'a [u8],
        errno: i32,
    },
    CoordinatorFdMove {
        errno: i32,
        placed: i32,
    },
    /// `RpcError::Closed` at any frame boundary of the handshake: before the
    /// acknowledgement (redeem refused, or another server-side check) or
    /// after it, before the Config frame. The client cannot tell which.
    CoordinatorClosedDuringHandshake,
    ConfigDigestMismatch(DigestCheck),
    /// Any other `RpcError`. It may own heap text, so this enum is not
    /// heap-free.
    Transport(RpcError),
    PtraceOnlyConfig,
    GuestPtraceNotRefused,
}

impl fmt::Display for AdmitError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        match self {
            AdmitError::Decode(e) => write!(f, "{e}"),
            AdmitError::FingerprintMismatch { packet, ours } => write!(
                f,
                "literoot initial packet config fingerprint {} is not this build's {}",
                text(packet),
                text(ours)
            ),
            AdmitError::CoordinatorCarriageDisagrees { packet, carriage } => write!(
                f,
                "literoot initial packet coordinator {} disagrees with the sealed carriage {}",
                text(packet),
                text(carriage)
            ),
            AdmitError::CoordinatorCarriageMalformed(name) => {
                write!(
                    f,
                    "literoot initial packet: coordinator carriage refused: {name}"
                )
            }
            AdmitError::CoordinatorUnreachable { path, errno } => write!(
                f,
                "literoot initial packet: coordinator {} unreachable: {}",
                text(path),
                io::Error::from_raw_os_error(*errno)
            ),
            AdmitError::CoordinatorFdMove { errno: 0, placed } => write!(
                f,
                "literoot initial packet: coordinator connection not placed in the runtime \
                 range: no free descriptor under the soft RLIMIT_NOFILE (it would sit at \
                 {placed})"
            ),
            AdmitError::CoordinatorFdMove { errno, .. } => write!(
                f,
                "literoot initial packet: coordinator connection not placed in the runtime \
                 range: {}",
                io::Error::from_raw_os_error(*errno)
            ),
            AdmitError::CoordinatorClosedDuringHandshake => f.write_str(
                "literoot initial packet: coordinator closed the connection during the \
                 InitialImage handshake (before or after its acknowledgement)",
            ),
            AdmitError::ConfigDigestMismatch(which) => write!(
                f,
                "literoot initial packet: coordinator Config differs from the expected digest \
                 ({})",
                match which {
                    DigestCheck::Ack => "acknowledgement",
                    DigestCheck::Config => "Config bytes",
                }
            ),
            AdmitError::Transport(e) => {
                write!(f, "literoot initial packet: coordinator transport: {e}")
            }
            AdmitError::PtraceOnlyConfig => f.write_str(
                "literoot initial packet: Config sets post_exec_at_exec_stop, which is \
                 ptrace-only",
            ),
            AdmitError::GuestPtraceNotRefused => f.write_str(
                "literoot initial packet: Config leaves guest ptrace unrefused, which \
                 in-guest must refuse",
            ),
        }
    }
}

fn classify(error: RpcError) -> AdmitError<'static> {
    match error {
        RpcError::Closed => AdmitError::CoordinatorClosedDuringHandshake,
        RpcError::Io(io_error) if io_error.kind() == io::ErrorKind::InvalidData => {
            match io_error.get_ref().map(|inner| inner.to_string()).as_deref() {
                Some(ACK_DIGEST_MISMATCH) => AdmitError::ConfigDigestMismatch(DigestCheck::Ack),
                Some(CONFIG_DIGEST_MISMATCH) => {
                    AdmitError::ConfigDigestMismatch(DigestCheck::Config)
                }
                _ => AdmitError::Transport(RpcError::Io(io_error)),
            }
        }
        other => AdmitError::Transport(other),
    }
}

/// The in-guest qualification of the delivered Config.
pub fn qualify(config: &LiterootConfig) -> Result<(), AdmitError<'static>> {
    if config.post_exec_at_exec_stop {
        return Err(AdmitError::PtraceOnlyConfig);
    }
    if !config.refuse_guest_ptrace {
        return Err(AdmitError::GuestPtraceNotRefused);
    }
    Ok(())
}

/// An admitted first image: the redeemed client and the coordinator path.
pub struct Admitted<S> {
    pub client: InitialImageClient<LiterootGlobal, S>,
    pub coordinator: PathBuf,
}

/// Admits a mapped first image, in this order (A1-A7): decode; compare the
/// fingerprint before connecting; check the carriage; connect (and place);
/// redeem with the packet's nonce and `*packet.config_digest`; qualify the
/// delivered Config; return the client and the path.
pub fn admit_initial<'a, S, C>(
    packet: &'a [u8],
    carriage: Carriage<'a>,
    tid: reverie::Pid,
    connect: C,
) -> Result<Admitted<S>, AdmitError<'a>>
where
    S: Read + Write + Send,
    C: FnOnce(&Path) -> Result<S, ConnectError>,
{
    // A1
    let packet = decode(packet).map_err(AdmitError::Decode)?;
    // A2
    let ours = literoot_config_wire_fingerprint();
    if packet.fingerprint != ours {
        return Err(AdmitError::FingerprintMismatch {
            packet: *packet.fingerprint,
            ours: *ours,
        });
    }
    // A3
    match carriage {
        Carriage::Absent => {}
        Carriage::Present(path) if path == packet.coordinator => {}
        Carriage::Present(path) => {
            return Err(AdmitError::CoordinatorCarriageDisagrees {
                packet: packet.coordinator,
                carriage: path,
            });
        }
        Carriage::Malformed(name) => return Err(AdmitError::CoordinatorCarriageMalformed(name)),
    }
    // A4
    let path = Path::new(OsStr::from_bytes(packet.coordinator));
    let stream = connect(path).map_err(|error| match error {
        ConnectError::Unreachable(errno) => AdmitError::CoordinatorUnreachable {
            path: packet.coordinator,
            errno,
        },
        ConnectError::FdMove { errno, placed } => AdmitError::CoordinatorFdMove { errno, placed },
    })?;
    // A5
    let client = BlockingRpcClient::<LiterootGlobal, S>::initial_image_from_connected_stream(
        stream,
        tid,
        packet.nonce,
        *packet.config_digest,
    )
    .map_err(classify)?;
    // A6
    qualify(client.config())?;
    // A7
    Ok(Admitted {
        client,
        coordinator: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &[u8] = b"/run/literoot/coordinator.sock";

    fn fp() -> [u8; FINGERPRINT_LEN] {
        *literoot_config_wire_fingerprint()
    }

    fn packet_with(path: &[u8], fingerprint: &[u8; FINGERPRINT_LEN]) -> Vec<u8> {
        encode(&[0x11; NONCE_LEN], &[0x22; 32], fingerprint, path).unwrap()
    }

    /// A valid packet of exactly 120 bytes (n = 26).
    fn packet120() -> Vec<u8> {
        let path = b"/run/literoot/abcdefghijkl";
        assert_eq!(path.len(), 26);
        let p = packet_with(path, b"0123456789abcdef");
        assert_eq!(p.len(), 120);
        p
    }

    // ----- decode -----

    #[test]
    fn decode_round_trips_encode() {
        let p = packet_with(PATH, b"0123456789abcdef");
        let d = decode(&p).unwrap();
        assert_eq!(d.nonce, &[0x11; NONCE_LEN]);
        assert_eq!(d.config_digest, &[0x22; 32]);
        assert_eq!(d.fingerprint, b"0123456789abcdef");
        assert_eq!(d.coordinator, PATH);
    }

    #[test]
    fn decode_accepts_the_boundaries() {
        let f = b"0123456789abcdef";
        for path in [
            b"/a".to_vec(),
            [b"/".to_vec(), vec![b'x'; 106]].concat(),
            b"/\xff\xfe-not-utf8".to_vec(),
        ] {
            let p = packet_with(&path, f);
            assert_eq!(decode(&p).unwrap().coordinator, &path[..]);
        }
        let p = encode(&[0; NONCE_LEN], &[0; 32], f, PATH).unwrap();
        assert_eq!(decode(&p).unwrap().nonce, &[0; NONCE_LEN]);
    }

    fn set_total(p: &mut [u8], total: usize) {
        p[10..12].copy_from_slice(&(total as u16).to_be_bytes());
    }

    #[test]
    fn decode_refuses_each_step_by_name() {
        let good = packet_with(PATH, b"0123456789abcdef");
        // D1. The 202-byte packet is otherwise well formed (total 202, n = 108,
        // an absolute NUL-free path), so D1's upper bound alone refuses it.
        assert_eq!(decode(&good[..93]), Err(DecodeError::Size));
        let long = raw_packet(
            &[b"/".to_vec(), vec![b'x'; 107]].concat(),
            b"0123456789abcdef",
        );
        assert_eq!(long.len(), 202);
        assert_eq!(decode(&long), Err(DecodeError::Size));
        // A 93-byte packet whose total field says 93: D1's lower bound alone
        // refuses it as Size (without it, D5 would answer Length).
        let mut short = good[..93].to_vec();
        set_total(&mut short, 93);
        assert_eq!(decode(&short), Err(DecodeError::Size));
        // D2
        let mut p = good.clone();
        p[..8].copy_from_slice(b"HLIINIT1");
        assert_eq!(decode(&p), Err(DecodeError::Magic));
        // D3
        for version in [0u16, 2] {
            let mut p = good.clone();
            p[8..10].copy_from_slice(&version.to_be_bytes());
            assert_eq!(decode(&p), Err(DecodeError::Version));
        }
        // D4
        for delta in [-1i64, 1] {
            let mut p = good.clone();
            set_total(&mut p, (good.len() as i64 + delta) as usize);
            assert_eq!(decode(&p), Err(DecodeError::Size));
        }
        // D5
        for n in [PATH.len() - 1, PATH.len() + 1] {
            let mut p = good.clone();
            p[92..94].copy_from_slice(&(n as u16).to_be_bytes());
            assert_eq!(decode(&p), Err(DecodeError::Length));
        }
        // D6
        for path in [&b"a/b"[..], b"/"] {
            let p = raw_packet(path, b"0123456789abcdef");
            assert_eq!(decode(&p), Err(DecodeError::Path), "{path:?}");
        }
        for at in [0, PATH.len() / 2, PATH.len() - 1] {
            let mut path = PATH.to_vec();
            path[at] = 0;
            let p = raw_packet(&path, b"0123456789abcdef");
            assert_eq!(decode(&p), Err(DecodeError::Path), "NUL at {at}");
        }
        // D7
        for f in [
            b"0123456789abcdeg",
            b"0123456789abcdeA",
            b"0123456789abcde\0",
        ] {
            let p = raw_packet(PATH, f);
            assert_eq!(decode(&p), Err(DecodeError::Fingerprint), "{f:?}");
        }
    }

    /// A packet built without `encode`'s checks, for decode negatives.
    fn raw_packet(path: &[u8], fingerprint: &[u8; FINGERPRINT_LEN]) -> Vec<u8> {
        let total = HEADER_LEN + path.len();
        let mut p = Vec::new();
        p.extend_from_slice(&MAGIC);
        p.extend_from_slice(&VERSION.to_be_bytes());
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x11; NONCE_LEN]);
        p.extend_from_slice(&[0x22; 32]);
        p.extend_from_slice(fingerprint);
        p.extend_from_slice(&(path.len() as u16).to_be_bytes());
        p.extend_from_slice(path);
        p
    }

    #[test]
    fn decode_classifies_short_paths_as_path() {
        assert_eq!(
            decode(&raw_packet(b"a", b"0123456789abcdef")),
            Err(DecodeError::Path)
        );
        assert_eq!(
            decode(&raw_packet(b"/", b"0123456789abcdef")),
            Err(DecodeError::Path)
        );
    }

    #[test]
    fn chosen_offsets_flip_to_their_class() {
        let good = packet120();
        let cases: &[(&[usize], u8, Option<DecodeError>)] = &[
            (&[0, 7], 0x00, Some(DecodeError::Magic)),
            (&[8, 9], 0xff, Some(DecodeError::Version)),
            (&[10, 11], 0xff, Some(DecodeError::Size)),
            (&[12, 43, 44, 75], 0xa5, None),
            (&[76, 91], b'G', Some(DecodeError::Fingerprint)),
            (&[92, 93], 0xff, Some(DecodeError::Length)),
            (&[94], b'a', Some(DecodeError::Path)),
            (&[100], 0x00, Some(DecodeError::Path)),
        ];
        for &(offsets, value, expected) in cases {
            for &at in offsets {
                let mut p = good.clone();
                p[at] = value;
                match expected {
                    Some(class) => assert_eq!(decode(&p), Err(class), "offset {at}"),
                    None => {
                        let d = decode(&p).unwrap();
                        let field: &[u8] = if at < DIGEST_AT {
                            &d.nonce[..]
                        } else {
                            &d.config_digest[..]
                        };
                        let within = if at < DIGEST_AT {
                            at - NONCE_AT
                        } else {
                            at - DIGEST_AT
                        };
                        assert_eq!(field[within], value, "offset {at}");
                    }
                }
            }
        }
    }

    // ----- encode -----

    #[test]
    fn encode_refuses_each_step_by_name() {
        let f = b"0123456789abcdef";
        let n = [0; NONCE_LEN];
        let d = [0; 32];
        let long = [b"/".to_vec(), vec![b'x'; 107]].concat();
        assert_eq!(long.len(), 108);
        assert_eq!(encode(&n, &d, f, &long), Err(EncodeError::PathLength));
        assert_eq!(encode(&n, &d, f, b"/"), Err(EncodeError::PathLength));
        assert_eq!(encode(&n, &d, f, b"a/b"), Err(EncodeError::Path));
        assert_eq!(encode(&n, &d, f, b"/a\0b"), Err(EncodeError::Path));
        assert_eq!(
            encode(&n, &d, b"0123456789ABCDEF", PATH),
            Err(EncodeError::Fingerprint)
        );
        assert_eq!(
            encode(&n, &d, b"0123456789abcdeg", PATH),
            Err(EncodeError::Fingerprint)
        );
    }

    // ----- fingerprint -----

    #[test]
    fn fingerprint_is_deterministic_and_lower_hex() {
        assert_eq!(
            literoot_config_wire_fingerprint(),
            literoot_config_wire_fingerprint()
        );
        assert!(is_lower_hex(literoot_config_wire_fingerprint()));
    }

    /// The production function equals the helper over the four domains,
    /// each payload built here and not taken from the production list, so a
    /// domain dropped from (or reordered in) the production call fails.
    #[test]
    fn fingerprint_is_the_helper_over_four_independent_domains() {
        let wire = codec::encode(&canonical_config()).unwrap();
        let json = CONFIG_JSON.as_bytes().to_vec();
        let revision = REFUSAL_RPC_REVISION.to_le_bytes().to_vec();
        let mut refusals = Vec::new();
        for refused in canonical_refusals() {
            let bytes = codec::encode(&refused).unwrap();
            refusals.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            refusals.extend_from_slice(&bytes);
        }
        let expected = hex16(hash_domains(&[
            (b"literoot.config.wire.v1", &wire),
            (b"literoot.config.json.v1", &json),
            (b"literoot.refusal.rpc.revision", &revision),
            (b"literoot.refusal.rpc.wire.v1", &refusals),
        ]));
        assert_eq!(literoot_config_wire_fingerprint(), &expected);
    }

    #[test]
    fn hash_domains_separates_payloads_tags_and_boundaries() {
        let base = hash_domains(&[(b"t1", b"p1"), (b"t2", b"p2")]);
        assert_ne!(base, hash_domains(&[(b"t1", b"p1"), (b"t2", b"p3")]));
        assert_ne!(base, hash_domains(&[(b"t1", b"p1"), (b"t3", b"p2")]));
        assert_ne!(base, hash_domains(&[(b"t2", b"p2"), (b"t1", b"p1")]));
        assert_ne!(
            hash_domains(&[(b"a", b"bc")]),
            hash_domains(&[(b"ab", b"c")])
        );
        assert_ne!(
            hash_domains(&[(b"t", b"ab"), (b"t", b"c")]),
            hash_domains(&[(b"t", b"a"), (b"t", b"bc")])
        );
        // Without the tag length, one tag can absorb a whole domain: both
        // sides would hash "t1" le64(2) "p1" "t2" le64(2) "p2".
        let len2 = 2u64.to_le_bytes();
        let tag_absorbs = [&b"t1"[..], &len2, b"p1", b"t2"].concat();
        assert_ne!(
            hash_domains(&[(&tag_absorbs, b"p2")]),
            hash_domains(&[(b"t1", b"p1"), (b"t2", b"p2")])
        );
        // Without the payload length, one payload can absorb the next
        // domain: both sides would hash le64(2) "t1" "p1" le64(2) "t2" "p2".
        let payload_absorbs = [&b"p1"[..], &len2, b"t2", b"p2"].concat();
        assert_ne!(
            hash_domains(&[(b"t1", &payload_absorbs)]),
            hash_domains(&[(b"t1", b"p1"), (b"t2", b"p2")])
        );
    }

    #[test]
    fn canonical_refusals_have_one_value_per_variant() {
        let all = canonical_refusals();
        assert_eq!(all.len(), 18);
        let mut tags: Vec<u8> = all.iter().map(|r| refusal_tag(r.0[0])).collect();
        tags.sort();
        assert_eq!(tags, (0..18).collect::<Vec<u8>>());
    }

    #[test]
    fn digest_mismatch_texts_are_reveries() {
        // reverie-rpc-transport initial_image.rs:97 and blocking_client.rs:410
        // at c5eff334 (unchanged since ac8b35c2). A rewording there fails this, rather than silently
        // turning the refusal into Transport.
        let ack = classify(RpcError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "InitialImage acknowledgement config digest mismatch",
        )));
        assert!(matches!(
            ack,
            AdmitError::ConfigDigestMismatch(DigestCheck::Ack)
        ));
        let config = classify(RpcError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "InitialImage raw config digest mismatch",
        )));
        assert!(matches!(
            config,
            AdmitError::ConfigDigestMismatch(DigestCheck::Config)
        ));
    }

    // ----- admit_initial -----

    struct FakeStream {
        input: io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for FakeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for FakeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        [
            (payload.len() as u32).to_be_bytes().to_vec(),
            payload.to_vec(),
        ]
        .concat()
    }

    fn ack(digest: &[u8; 32]) -> Vec<u8> {
        frame(&[&b"RVINITAK"[..], &1u16.to_be_bytes(), digest].concat())
    }

    fn in_guest_config() -> LiterootConfig {
        LiterootConfig {
            post_exec_at_exec_stop: false,
            refuse_guest_ptrace: true,
            ..canonical_config()
        }
    }

    /// The coordinator's side: the acknowledgement for `ack_digest`, then
    /// the Config frame for `config`, or the stream closed earlier.
    enum Script {
        CloseBeforeAck,
        AckThenClose,
        Full,
    }

    fn coordinator(config: &LiterootConfig, ack_digest: [u8; 32], script: Script) -> FakeStream {
        let config_bytes = codec::encode(config).unwrap();
        let input = match script {
            Script::CloseBeforeAck => Vec::new(),
            Script::AckThenClose => ack(&ack_digest),
            Script::Full => [ack(&ack_digest), frame(&config_bytes)].concat(),
        };
        FakeStream {
            input: io::Cursor::new(input),
            written: Vec::new(),
        }
    }

    fn digest_of(config: &LiterootConfig) -> [u8; 32] {
        reverie_rpc_transport::initial_image::config_digest(&codec::encode(config).unwrap())
    }

    fn packet_for(config: &LiterootConfig) -> Vec<u8> {
        encode(&[0x5a; NONCE_LEN], &digest_of(config), &fp(), PATH).unwrap()
    }

    fn tid() -> reverie::Pid {
        reverie::Pid::from_raw(4242)
    }

    type Admit<'a> = Result<Admitted<FakeStream>, AdmitError<'a>>;

    fn admit<'a>(
        packet: &'a [u8],
        carriage: Carriage<'a>,
        stream: Result<FakeStream, ConnectError>,
        called: &mut Option<PathBuf>,
    ) -> Admit<'a> {
        admit_initial(packet, carriage, tid(), |path: &Path| {
            *called = Some(path.to_path_buf());
            stream
        })
    }

    #[test]
    fn fingerprint_mismatch_never_connects() {
        let config = in_guest_config();
        let p = encode(
            &[0; NONCE_LEN],
            &digest_of(&config),
            b"0000000000000000",
            PATH,
        )
        .unwrap();
        let mut called = None;
        let r = admit(
            &p,
            Carriage::Absent,
            Ok(coordinator(&config, digest_of(&config), Script::Full)),
            &mut called,
        );
        assert!(matches!(r, Err(AdmitError::FingerprintMismatch { .. })));
        assert_eq!(called, None);
    }

    #[test]
    fn carriage_disagreement_and_malformed_carriage_never_connect() {
        let config = in_guest_config();
        let p = packet_for(&config);
        let mut called = None;
        let r = admit(
            &p,
            Carriage::Present(b"/elsewhere"),
            Ok(coordinator(&config, digest_of(&config), Script::Full)),
            &mut called,
        );
        assert!(matches!(
            r,
            Err(AdmitError::CoordinatorCarriageDisagrees { .. })
        ));
        assert_eq!(called, None);
        // Equal length, last byte different; and a strict prefix of PATH.
        let mut last_byte = PATH.to_vec();
        *last_byte.last_mut().unwrap() ^= 1;
        for carriage in [&last_byte[..], &PATH[..PATH.len() - 1]] {
            let r = admit(
                &p,
                Carriage::Present(carriage),
                Ok(coordinator(&config, digest_of(&config), Script::Full)),
                &mut called,
            );
            assert!(matches!(
                r,
                Err(AdmitError::CoordinatorCarriageDisagrees { .. })
            ));
            assert_eq!(called, None);
        }
        // N3-4: Reverie's real refusal name for Err(Duplicate).
        let r = admit(
            &p,
            Carriage::Malformed("mapped_coordinator_path_duplicate"),
            Ok(coordinator(&config, digest_of(&config), Script::Full)),
            &mut called,
        );
        assert!(matches!(
            r,
            Err(AdmitError::CoordinatorCarriageMalformed(
                "mapped_coordinator_path_duplicate"
            ))
        ));
        assert_eq!(called, None);
    }

    #[test]
    fn absent_or_equal_carriage_admits() {
        let config = in_guest_config();
        let p = packet_for(&config);
        for carriage in [Carriage::Absent, Carriage::Present(PATH)] {
            let mut called = None;
            let r = admit(
                &p,
                carriage,
                Ok(coordinator(&config, digest_of(&config), Script::Full)),
                &mut called,
            );
            let admitted = r.unwrap();
            assert_eq!(admitted.coordinator, Path::new(OsStr::from_bytes(PATH)));
            assert_eq!(called.as_deref(), Some(Path::new(OsStr::from_bytes(PATH))));
            assert_eq!(admitted.client.config().rootfs, config.rootfs);
            // A5 wrote exactly one frame, the redemption of the packet's
            // nonce, and the client carries the image's tid.
            let client = admitted.client.into_client();
            let spent =
                client.replace_stream(coordinator(&config, [0; 32], Script::CloseBeforeAck));
            let redemption =
                reverie_rpc_transport::initial_image::encode_redemption(&[0x5a; NONCE_LEN])
                    .unwrap();
            assert_eq!(spent.written, frame(&redemption));
            assert_eq!(client.tid(), tid());
        }
    }

    #[test]
    fn connector_failures_keep_their_class() {
        let config = in_guest_config();
        let p = packet_for(&config);
        let mut called = None;
        let r = admit(
            &p,
            Carriage::Absent,
            Err(ConnectError::Unreachable(libc::ENOENT)),
            &mut called,
        );
        assert!(matches!(
            r,
            Err(AdmitError::CoordinatorUnreachable {
                errno: libc::ENOENT,
                ..
            })
        ));
        let r = admit(
            &p,
            Carriage::Absent,
            Err(ConnectError::FdMove {
                errno: 0,
                placed: 1008,
            }),
            &mut called,
        );
        assert!(matches!(
            r,
            Err(AdmitError::CoordinatorFdMove {
                errno: 0,
                placed: 1008
            })
        ));
    }

    #[test]
    fn a_close_anywhere_in_the_handshake_is_closed_during_handshake() {
        let config = in_guest_config();
        let p = packet_for(&config);
        for script in [Script::CloseBeforeAck, Script::AckThenClose] {
            let mut called = None;
            let r = admit(
                &p,
                Carriage::Absent,
                Ok(coordinator(&config, digest_of(&config), script)),
                &mut called,
            );
            assert!(matches!(
                r,
                Err(AdmitError::CoordinatorClosedDuringHandshake)
            ));
        }
    }

    #[test]
    fn the_packet_digest_is_the_expected_digest() {
        let config = in_guest_config();
        let p = packet_for(&config);
        let mut called = None;
        // The coordinator acknowledges a different digest.
        let r = admit(
            &p,
            Carriage::Absent,
            Ok(coordinator(&config, [0x77; 32], Script::Full)),
            &mut called,
        );
        assert!(matches!(
            r,
            Err(AdmitError::ConfigDigestMismatch(DigestCheck::Ack))
        ));
        // It acknowledges the packet's digest but sends other Config bytes.
        let other = LiterootConfig {
            cwd: "/other".into(),
            ..in_guest_config()
        };
        let r = admit(
            &p,
            Carriage::Absent,
            Ok(coordinator(&other, digest_of(&config), Script::Full)),
            &mut called,
        );
        assert!(matches!(
            r,
            Err(AdmitError::ConfigDigestMismatch(DigestCheck::Config))
        ));
    }

    #[test]
    fn a_wrong_ack_magic_is_transport_not_digest() {
        let config = in_guest_config();
        let p = packet_for(&config);
        let config_bytes = codec::encode(&config).unwrap();
        let bad_ack = frame(&[&b"RVINITXX"[..], &1u16.to_be_bytes(), &digest_of(&config)].concat());
        let stream = FakeStream {
            input: io::Cursor::new([bad_ack, frame(&config_bytes)].concat()),
            written: Vec::new(),
        };
        let mut called = None;
        let r = admit(&p, Carriage::Absent, Ok(stream), &mut called);
        assert!(matches!(r, Err(AdmitError::Transport(_))), "{:?}", r.err());
    }

    #[test]
    fn qualification_refuses_after_the_handshake() {
        for (config, ptrace_only) in [
            (
                LiterootConfig {
                    post_exec_at_exec_stop: true,
                    ..in_guest_config()
                },
                true,
            ),
            (
                LiterootConfig {
                    refuse_guest_ptrace: false,
                    ..in_guest_config()
                },
                false,
            ),
        ] {
            let p = packet_for(&config);
            let mut called = None;
            let r = admit(
                &p,
                Carriage::Absent,
                Ok(coordinator(&config, digest_of(&config), Script::Full)),
                &mut called,
            );
            // Connect ran; the A6 refusal below can only follow a completed
            // handshake, because qualification reads the Config that A5
            // delivered.
            assert!(called.is_some(), "connect ran");
            if ptrace_only {
                assert!(matches!(r, Err(AdmitError::PtraceOnlyConfig)));
            } else {
                assert!(matches!(r, Err(AdmitError::GuestPtraceNotRefused)));
            }
        }
    }

    #[test]
    fn a_malformed_packet_is_refused_by_name_before_anything_else() {
        let config = in_guest_config();
        let good = packet_for(&config);
        let flip = |at: usize, value: u8| {
            let mut p = good.clone();
            p[at] = value;
            p
        };
        let magic = flip(0, b'M');
        let version = flip(9, 0);
        let length = flip(PATH_LEN_AT + 1, good[PATH_LEN_AT + 1] ^ 1);
        let path = flip(HEADER_LEN, b'x');
        let fingerprint = flip(FINGERPRINT_AT, b'G');
        for (bytes, class) in [
            (&good[..0], DecodeError::Size),
            (&good[..93], DecodeError::Size),
            (&magic[..], DecodeError::Magic),
            (&version[..], DecodeError::Version),
            (&length[..], DecodeError::Length),
            (&path[..], DecodeError::Path),
            (&fingerprint[..], DecodeError::Fingerprint),
        ] {
            // A disagreeing carriage too: A1 answers before A3.
            let mut called = None;
            let r = admit(
                bytes,
                Carriage::Present(b"/elsewhere"),
                Ok(coordinator(&config, digest_of(&config), Script::Full)),
                &mut called,
            );
            assert!(
                matches!(r, Err(AdmitError::Decode(c)) if c == class),
                "{class:?}"
            );
            assert_eq!(called, None, "{class:?}");
        }
    }

    /// Every combination of eight faults, one per admission check in A1-A6
    /// order: the refusal is always the earliest fault present, and connect
    /// runs exactly when A1-A3 pass.
    #[test]
    fn refusal_precedence_is_the_check_order_for_every_fault_combination() {
        const FAULTS: [&str; 8] = [
            "decode",
            "fingerprint",
            "carriage",
            "connect",
            "close",
            "ack",
            "config",
            "qualify",
        ];
        let ptrace_only = || LiterootConfig {
            post_exec_at_exec_stop: true,
            ..in_guest_config()
        };
        for mask in 0u32..1 << FAULTS.len() {
            let has =
                |name: &str| mask & (1 << FAULTS.iter().position(|f| *f == name).unwrap()) != 0;
            // The packet's Config: one that fails qualification for "qualify".
            let config = if has("qualify") {
                ptrace_only()
            } else {
                in_guest_config()
            };
            let fingerprint = if has("fingerprint") {
                *b"0000000000000000"
            } else {
                fp()
            };
            let mut p =
                encode(&[0x5a; NONCE_LEN], &digest_of(&config), &fingerprint, PATH).unwrap();
            if has("decode") {
                p[0] = b'M';
            }
            let carriage = if has("carriage") {
                Carriage::Present(b"/elsewhere")
            } else {
                Carriage::Absent
            };
            // "config": the coordinator sends the other Config, whose digest
            // differs from the one acknowledged.
            let sent = match (has("config"), has("qualify")) {
                (false, _) => config.clone(),
                (true, true) => in_guest_config(),
                (true, false) => ptrace_only(),
            };
            let ack = if has("ack") {
                [0x77; 32]
            } else {
                digest_of(&config)
            };
            let script = if has("close") {
                Script::CloseBeforeAck
            } else {
                Script::Full
            };
            let stream = if has("connect") {
                Err(ConnectError::Unreachable(111))
            } else {
                Ok(coordinator(&sent, ack, script))
            };
            let mut called = None;
            let got = match admit(&p, carriage, stream, &mut called) {
                Ok(_) => "admitted",
                Err(AdmitError::Decode(DecodeError::Magic)) => "decode",
                Err(AdmitError::FingerprintMismatch { .. }) => "fingerprint",
                Err(AdmitError::CoordinatorCarriageDisagrees { .. }) => "carriage",
                Err(AdmitError::CoordinatorUnreachable { errno: 111, .. }) => "connect",
                Err(AdmitError::CoordinatorClosedDuringHandshake) => "close",
                Err(AdmitError::ConfigDigestMismatch(DigestCheck::Ack)) => "ack",
                Err(AdmitError::ConfigDigestMismatch(DigestCheck::Config)) => "config",
                Err(AdmitError::PtraceOnlyConfig) => "qualify",
                Err(e) => panic!("faults {mask:#010b}: unexpected refusal {e}"),
            };
            let want = FAULTS
                .iter()
                .copied()
                .find(|f| has(f))
                .unwrap_or("admitted");
            assert_eq!(got, want, "faults {mask:#010b}");
            let connects = !(has("decode") || has("fingerprint") || has("carriage"));
            assert_eq!(called.is_some(), connects, "faults {mask:#010b}");
        }
    }

    #[test]
    fn every_refusal_display_starts_with_the_prefix() {
        let errors: Vec<AdmitError<'static>> = vec![
            AdmitError::Decode(DecodeError::Size),
            AdmitError::FingerprintMismatch {
                packet: [b'0'; 16],
                ours: [b'1'; 16],
            },
            AdmitError::CoordinatorCarriageDisagrees {
                packet: b"/a",
                carriage: b"/b",
            },
            AdmitError::CoordinatorCarriageMalformed("mapped_coordinator_path_empty"),
            AdmitError::CoordinatorUnreachable {
                path: b"/a",
                errno: libc::ENOENT,
            },
            AdmitError::CoordinatorFdMove {
                errno: 0,
                placed: 1008,
            },
            AdmitError::CoordinatorFdMove {
                errno: libc::EMFILE,
                placed: -1,
            },
            AdmitError::CoordinatorClosedDuringHandshake,
            AdmitError::ConfigDigestMismatch(DigestCheck::Ack),
            AdmitError::Transport(RpcError::Closed),
            AdmitError::PtraceOnlyConfig,
            AdmitError::GuestPtraceNotRefused,
        ];
        for e in errors {
            assert!(e.to_string().starts_with("literoot initial packet"), "{e}");
        }
    }

    // ----- top band -----

    #[test]
    fn the_top_band_floor_follows_reveries_minimums() {
        assert_eq!(top_band_floor(u64::MAX), 1025);
        assert_eq!(top_band_floor(1033), 1025);
        assert_eq!(top_band_floor(1032), 1024);
        assert_eq!(top_band_floor(1024), 1016);
        assert_eq!(top_band_floor(16), 8);
        assert_eq!(top_band_floor(8), 3);
        assert_eq!(reverie_inguest::guest::protect::RUNTIME_FD_MIN, 1025);
    }
}
