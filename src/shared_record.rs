//! Bounded canonical snapshot of literoot's *shared* facts.
//!
//! B4 deliberately separates two kinds of continuity state:
//! per-process state travels in [`ExecState`], while facts
//! visible across the guest process tree belong here. This
//! module defines the values, their identity and bounds, the
//! deterministic snapshot encoding, and the first file-backed
//! transport: a launcher-created memfd holding exactly one
//! length-framed snapshot. It is not an in-place shared-memory
//! layout; every operation reloads or rewrites the bounded
//! snapshot while holding an open-file-description lock.
//!
//! Process identity is `(pid, start_time)`, never a bare pid:
//! pid reuse must not alias a dead predecessor's exe/argv row.
//! The unit/epoch of `start_time` is supplied by the transport
//! that learns it (for example `stat` start-time ticks); this
//! codec only preserves and compares the opaque value.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::OnceLock;

use crate::exec_state::ExecState;

/// Wire magic (`"LRS1"`).
pub const MAGIC: &[u8; 4] = b"LRS1";
/// Only supported shared-record snapshot version.
pub const VERSION: u16 = 1;
/// Hard cap on one encoded shared-record snapshot.
pub const MAX_ENCODED_BYTES: usize = 1024 * 1024;
/// Hard cap on process-directory rows in one snapshot.
pub const MAX_PROCESSES: usize = 4096;
/// Linux `__NEW_UTS_LEN` payload bound for one UTS name field.
pub const MAX_UTS_BYTES: usize = 64;

const FLAG_HAS_NODENAME: u16 = 1 << 0;
const FLAG_HAS_DOMAINNAME: u16 = 1 << 1;

/// Start-time-qualified guest process identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessId {
    pub pid: i32,
    pub start_time: u64,
}

impl ProcessId {
    pub fn new(pid: i32, start_time: u64) -> Result<Self, SharedRecordError> {
        let id = Self { pid, start_time };
        id.validate()?;
        Ok(id)
    }

    fn validate(&self) -> Result<(), SharedRecordError> {
        if self.pid <= 0 {
            Err(SharedRecordError::InvalidProcessId)
        } else {
            Ok(())
        }
    }
}

/// One process directory row: the row a process publishes for
/// itself after launch, fork seeding, or exec restore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessRecord {
    pub id: ProcessId,
    pub exe_guest: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
}

impl ProcessRecord {
    pub fn from_exec_state(id: ProcessId, state: &ExecState) -> Result<Self, SharedRecordError> {
        let record = Self {
            id,
            exe_guest: state.exe_guest.clone(),
            argv: state.argv.clone(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), SharedRecordError> {
        self.id.validate()?;
        validate_exe(&self.exe_guest)
    }
}

/// Shared, cross-process facts only. In particular, this is
/// not a second copy of any one process's cwd, fds, root
/// override, or fake identity; those remain in `ExecState`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedRecord {
    pub uts_nodename: Option<Vec<u8>>,
    pub uts_domainname: Option<Vec<u8>>,
    /// Sorted by qualified process identity. Private so
    /// lookups can rely on the invariant outside this module;
    /// entry points below also canonicalize defensively.
    processes: Vec<ProcessRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedRecordError {
    BadMagic,
    UnsupportedVersion(u16),
    Truncated,
    TrailingBytes,
    TooLarge,
    TooManyProcesses,
    UnsortedOrDuplicateProcess,
    InvalidProcessId,
    RelativePath,
    InvalidUtsLength,
    Malformed,
}

impl std::fmt::Display for SharedRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "shared-record: bad magic"),
            Self::UnsupportedVersion(v) => {
                write!(f, "shared-record: unsupported version {v}")
            }
            Self::Truncated => write!(f, "shared-record: truncated input"),
            Self::TrailingBytes => write!(f, "shared-record: trailing bytes"),
            Self::TooLarge => write!(f, "shared-record: over size cap"),
            Self::TooManyProcesses => write!(f, "shared-record: too many processes"),
            Self::UnsortedOrDuplicateProcess => {
                write!(f, "shared-record: process rows unsorted or duplicate")
            }
            Self::InvalidProcessId => write!(f, "shared-record: non-positive pid"),
            Self::RelativePath => write!(f, "shared-record: relative guest exe path"),
            Self::InvalidUtsLength => write!(f, "shared-record: UTS field over 64 bytes"),
            Self::Malformed => write!(f, "shared-record: malformed field"),
        }
    }
}

impl std::error::Error for SharedRecordError {}

impl SharedRecord {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a record from arbitrary in-memory parts,
    /// canonicalizing row order before validation. This is
    /// the one bulk constructor; later insertions go through
    /// `publish`, which maintains the same order.
    pub fn from_parts(
        uts_nodename: Option<Vec<u8>>,
        uts_domainname: Option<Vec<u8>>,
        processes: Vec<ProcessRecord>,
    ) -> Result<Self, SharedRecordError> {
        let mut record = Self {
            uts_nodename,
            uts_domainname,
            processes,
        };
        record.canonicalize_processes();
        record.validate()?;
        Ok(record)
    }

    pub fn processes(&self) -> &[ProcessRecord] {
        &self.processes
    }

    fn canonicalize_processes(&mut self) {
        self.processes.sort_by_key(|row| row.id);
    }

    /// A one-row bootstrap snapshot containing only `id`'s own
    /// directory row. UTS facts are left unset: knowing one's
    /// own exe/argv does not make a namespace name authoritative.
    pub fn bootstrap_from_exec_state(
        id: ProcessId,
        state: &ExecState,
    ) -> Result<Self, SharedRecordError> {
        let mut record = Self::new();
        record.publish_exec_state(id, state)?;
        Ok(record)
    }

    pub fn set_uts_nodename(&mut self, name: Option<Vec<u8>>) -> Result<(), SharedRecordError> {
        validate_uts(name.as_deref())?;
        self.uts_nodename = name;
        Ok(())
    }

    pub fn set_uts_domainname(&mut self, name: Option<Vec<u8>>) -> Result<(), SharedRecordError> {
        validate_uts(name.as_deref())?;
        self.uts_domainname = name;
        Ok(())
    }

    /// Insert or replace exactly the row qualified by
    /// `(pid, start_time)`. A reused numeric pid with another
    /// start time is a distinct row, never an overwrite.
    /// Publish has no per-row byte limit: one oversized row may
    /// be present in memory while `encode` refuses the whole
    /// snapshot `TooLarge`. It is never truncated or reaped
    /// implicitly; a transport that needs bootstrap bytes must
    /// surface that named refusal (or remove the row) itself.
    pub fn publish(&mut self, record: ProcessRecord) -> Result<(), SharedRecordError> {
        record.validate()?;
        self.canonicalize_processes();
        match self
            .processes
            .binary_search_by_key(&record.id, |row| row.id)
        {
            Ok(index) => {
                self.processes[index] = record;
                Ok(())
            }
            Err(index) => {
                if self.processes.len() >= MAX_PROCESSES {
                    return Err(SharedRecordError::TooManyProcesses);
                }
                self.processes.insert(index, record);
                Ok(())
            }
        }
    }

    pub fn publish_exec_state(
        &mut self,
        id: ProcessId,
        state: &ExecState,
    ) -> Result<(), SharedRecordError> {
        self.publish(ProcessRecord::from_exec_state(id, state)?)
    }

    pub fn lookup(&self, id: ProcessId) -> Option<&ProcessRecord> {
        // Linear on purpose: lookup takes `&self`, so it cannot
        // restore order if an in-module caller bypassed the
        // constructors. Returning a present row is more
        // important here than exploiting the usual invariant.
        self.processes.iter().find(|row| row.id == id)
    }

    pub fn remove(&mut self, id: ProcessId) -> bool {
        self.canonicalize_processes();
        match self.processes.binary_search_by_key(&id, |row| row.id) {
            Ok(index) => {
                self.processes.remove(index);
                true
            }
            Err(_) => false,
        }
    }

    fn validate(&self) -> Result<(), SharedRecordError> {
        validate_uts(self.uts_nodename.as_deref())?;
        validate_uts(self.uts_domainname.as_deref())?;
        if self.processes.len() > MAX_PROCESSES {
            return Err(SharedRecordError::TooManyProcesses);
        }
        let mut previous: Option<ProcessId> = None;
        for record in &self.processes {
            record.validate()?;
            if previous.is_some_and(|prev| prev >= record.id) {
                return Err(SharedRecordError::UnsortedOrDuplicateProcess);
            }
            previous = Some(record.id);
        }
        Ok(())
    }

    fn canonical(&self) -> Self {
        let mut record = self.clone();
        record.processes.sort_by_key(|row| row.id);
        record
    }

    /// Canonical snapshot encoding: deterministic for equal
    /// records, with input row order hidden exactly as in
    /// `ExecState::encode`. This is a bootstrap/exchange
    /// snapshot, not a claim about a future shared-memory
    /// layout or its synchronization protocol.
    pub fn encode(&self) -> Result<Vec<u8>, SharedRecordError> {
        let record = self.canonical();
        record.validate()?;
        let mut flags = 0u16;
        if record.uts_nodename.is_some() {
            flags |= FLAG_HAS_NODENAME;
        }
        if record.uts_domainname.is_some() {
            flags |= FLAG_HAS_DOMAINNAME;
        }
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        if let Some(name) = &record.uts_nodename {
            put_bytes(&mut out, name)?;
        }
        if let Some(name) = &record.uts_domainname {
            put_bytes(&mut out, name)?;
        }
        put_count(&mut out, record.processes.len())?;
        for row in &record.processes {
            out.extend_from_slice(&row.id.pid.to_le_bytes());
            out.extend_from_slice(&row.id.start_time.to_le_bytes());
            put_bytes(&mut out, &row.exe_guest)?;
            put_count(&mut out, row.argv.len())?;
            for arg in &row.argv {
                put_bytes(&mut out, arg)?;
            }
            if out.len() > MAX_ENCODED_BYTES {
                return Err(SharedRecordError::TooLarge);
            }
        }
        if out.len() > MAX_ENCODED_BYTES {
            return Err(SharedRecordError::TooLarge);
        }
        Ok(out)
    }

    /// Decode a canonical snapshot, checking every count and
    /// length against the remaining input before allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, SharedRecordError> {
        if bytes.len() > MAX_ENCODED_BYTES {
            return Err(SharedRecordError::TooLarge);
        }
        let mut reader = Reader { buf: bytes, pos: 0 };
        if reader.take(4)? != MAGIC.as_slice() {
            return Err(SharedRecordError::BadMagic);
        }
        let version = reader.u16()?;
        if version != VERSION {
            return Err(SharedRecordError::UnsupportedVersion(version));
        }
        let flags = reader.u16()?;
        if flags & !(FLAG_HAS_NODENAME | FLAG_HAS_DOMAINNAME) != 0 {
            return Err(SharedRecordError::Malformed);
        }
        let uts_nodename = if flags & FLAG_HAS_NODENAME != 0 {
            Some(reader.bytes()?.to_vec())
        } else {
            None
        };
        let uts_domainname = if flags & FLAG_HAS_DOMAINNAME != 0 {
            Some(reader.bytes()?.to_vec())
        } else {
            None
        };
        // Read the row count as a plain fixed-width field so the
        // explicit cap wins over the generic count-vs-remaining
        // truncation check: an over-cap count is TooManyProcesses
        // even when no row bytes follow it.
        let process_count = reader.u32()? as usize;
        if process_count > MAX_PROCESSES {
            return Err(SharedRecordError::TooManyProcesses);
        }
        if process_count > reader.remaining() {
            return Err(SharedRecordError::Truncated);
        }
        // Every row needs at least pid/start/exe-len/argv-count.
        if process_count > reader.remaining() / 20 {
            return Err(SharedRecordError::Truncated);
        }
        let mut processes = Vec::with_capacity(process_count);
        let mut previous: Option<ProcessId> = None;
        for _ in 0..process_count {
            let pid = reader.i32()?;
            let start_time = reader.u64()?;
            let id = ProcessId { pid, start_time };
            id.validate()?;
            if previous.is_some_and(|prev| prev >= id) {
                return Err(SharedRecordError::UnsortedOrDuplicateProcess);
            }
            previous = Some(id);
            let exe_guest = reader.bytes()?.to_vec();
            let argv = reader.byte_list()?;
            let row = ProcessRecord {
                id,
                exe_guest,
                argv,
            };
            row.validate()?;
            processes.push(row);
        }
        if reader.pos != bytes.len() {
            return Err(SharedRecordError::TrailingBytes);
        }
        let record = Self {
            uts_nodename,
            uts_domainname,
            processes,
        };
        record.validate()?;
        Ok(record)
    }
}

fn validate_exe(exe_guest: &[u8]) -> Result<(), SharedRecordError> {
    if exe_guest.first() == Some(&b'/') {
        Ok(())
    } else {
        Err(SharedRecordError::RelativePath)
    }
}

fn validate_uts(name: Option<&[u8]>) -> Result<(), SharedRecordError> {
    if name.is_some_and(|bytes| bytes.len() > MAX_UTS_BYTES) {
        Err(SharedRecordError::InvalidUtsLength)
    } else {
        Ok(())
    }
}

fn put_count(out: &mut Vec<u8>, count: usize) -> Result<(), SharedRecordError> {
    let count = u32::try_from(count).map_err(|_| SharedRecordError::TooLarge)?;
    out.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SharedRecordError> {
    put_count(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], SharedRecordError> {
        let end = self
            .pos
            .checked_add(count)
            .filter(|end| *end <= self.buf.len())
            .ok_or(SharedRecordError::Truncated)?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, SharedRecordError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, SharedRecordError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn i32(&mut self) -> Result<i32, SharedRecordError> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, SharedRecordError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<&'a [u8], SharedRecordError> {
        let len = self.count()?;
        self.take(len)
    }

    fn count(&mut self) -> Result<usize, SharedRecordError> {
        let count = self.u32()? as usize;
        if count > self.remaining() {
            return Err(SharedRecordError::Truncated);
        }
        Ok(count)
    }

    fn byte_list(&mut self) -> Result<Vec<Vec<u8>>, SharedRecordError> {
        let count = self.count()?;
        // Each item carries at least its own u32 length.
        if count > self.remaining() / 4 {
            return Err(SharedRecordError::Truncated);
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.bytes()?.to_vec());
        }
        Ok(values)
    }
}

/// Internal launcher-to-Tool environment variable carrying the
/// shared-record memfd number. It follows the existing
/// `LITEROOT_PROBE_GEN_FD` handoff shape: an inherited fd, not a
/// guest-visible pathname or CLI option.
pub const SHARED_RECORD_FD_ENV: &str = "LITEROOT_SHARED_RECORD_FD";

const FRAME_HEADER_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

fn file_identity(file: &File) -> std::io::Result<FileIdentity> {
    let meta = file.metadata()?;
    Ok(FileIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

fn identity_of_fd(fd: RawFd) -> std::io::Result<FileIdentity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstat` borrows the descriptor and writes only
    // through `stat`; an env-supplied closed/invalid number is
    // reported as EBADF instead of being wrapped in a File.
    let rc = unsafe { libc::fstat(fd, &mut stat) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileIdentity {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    })
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn lock_file(file: &File, exclusive: bool, wait: bool) -> std::io::Result<bool> {
    let mut request: libc::flock = unsafe { std::mem::zeroed() };
    request.l_type = (if exclusive {
        libc::F_WRLCK
    } else {
        libc::F_RDLCK
    }) as i16;
    request.l_whence = libc::SEEK_SET as i16;
    let cmd = if wait {
        libc::F_OFD_SETLKW
    } else {
        libc::F_OFD_SETLK
    };
    // SAFETY: `request` is a fully initialized flock for the
    // whole file; the descriptor remains open in `file`.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), cmd, &request) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if !wait && matches!(err.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EACCES)) {
        return Ok(false);
    }
    Err(err)
}

struct LockedFile {
    file: File,
}

impl LockedFile {
    fn read_snapshot(&self) -> std::io::Result<SharedRecord> {
        use std::os::unix::fs::FileExt;

        let len = self.file.metadata()?.len();
        if len < FRAME_HEADER_BYTES as u64 {
            return Err(invalid_data("shared-record: short frame header"));
        }
        if len > (FRAME_HEADER_BYTES + MAX_ENCODED_BYTES) as u64 {
            return Err(invalid_data("shared-record: frame exceeds snapshot cap"));
        }
        let mut header = [0u8; FRAME_HEADER_BYTES];
        self.file.read_exact_at(&mut header, 0)?;
        let payload_len = u64::from_le_bytes(header);
        if payload_len > MAX_ENCODED_BYTES as u64 {
            return Err(invalid_data("shared-record: snapshot payload over cap"));
        }
        if len != FRAME_HEADER_BYTES as u64 + payload_len {
            return Err(invalid_data("shared-record: frame length mismatch"));
        }
        let mut payload = vec![0u8; payload_len as usize];
        self.file
            .read_exact_at(&mut payload, FRAME_HEADER_BYTES as u64)?;
        SharedRecord::decode(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    fn write_snapshot(&self, record: &SharedRecord) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;

        let payload = record
            .encode()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut framed = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        framed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        framed.extend_from_slice(&payload);
        self.file.write_all_at(&framed, 0)?;
        self.file.set_len(framed.len() as u64)
    }
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        let mut request: libc::flock = unsafe { std::mem::zeroed() };
        request.l_type = libc::F_UNLCK as i16;
        request.l_whence = libc::SEEK_SET as i16;
        // SAFETY: best-effort unlock of this open description;
        // closing the File immediately afterwards would also
        // release an OFD lock.
        let _ = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_OFD_SETLK, &request) };
    }
}

/// Optional UTS `(nodename, domainname)` pair from one snapshot.
pub type UtsPair = (Option<Vec<u8>>, Option<Vec<u8>>);

/// A launcher-created memfd carrying one whole `SharedRecord`
/// snapshot. The file is intentionally rewritten under lock
/// instead of becoming a shared-memory layout: snapshot size
/// is bounded at 1 MiB, and all current mutation sites are
/// exec/fork/UTS transitions rather than the syscall hot path.
///
/// `fd` is borrowed for the process lifetime and is never
/// closed by this handle. Every operation instead reopens
/// `/proc/self/fd/<fd>`, yielding a distinct open file
/// description for OFD locking, and validates that its
/// `(st_dev, st_ino)` still equals the identity recorded when
/// the handle was created/adopted. Closing or replacing this
/// hosting process's number therefore fails closed to
/// callers' process-local fallbacks rather than writing some
/// other file. That is the in-guest guest-visible case; a
/// ptrace guest has a separate descriptor table from the
/// tracer-hosted Tool.
pub struct SharedRecordFile {
    fd: RawFd,
    identity: FileIdentity,
}

impl SharedRecordFile {
    pub fn create() -> std::io::Result<Self> {
        let name = std::ffi::CString::new("literoot-shared-record").unwrap();
        // SAFETY: the name is NUL-terminated for the call. No
        // MFD_CLOEXEC: descendants and guest execs must inherit.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let identity = match identity_of_fd(fd) {
            Ok(identity) => identity,
            Err(err) => {
                // SAFETY: creation just made this descriptor and
                // no other owner exists yet on this error path.
                unsafe { libc::close(fd) };
                return Err(err);
            }
        };
        let store = Self { fd, identity };
        if let Err(err) = store.replace(&SharedRecord::new()) {
            // SAFETY: creation just made this descriptor and no
            // other owner exists yet on this error path.
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(store)
    }

    pub fn from_env() -> Option<Self> {
        let raw = std::env::var(SHARED_RECORD_FD_ENV).ok()?;
        Self::from_env_value(Some(&raw))
    }

    fn from_env_value(raw: Option<&str>) -> Option<Self> {
        let fd: RawFd = raw?.parse().ok()?;
        if fd < 0 {
            return None;
        }
        let store = Self {
            fd,
            identity: identity_of_fd(fd).ok()?,
        };
        // Establishing the expected file's identity is part of
        // adoption: a malformed or replaced descriptor is
        // absent, not a partially trusted store.
        store.snapshot().ok()?;
        Some(store)
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    fn open_locked(&self, exclusive: bool) -> std::io::Result<LockedFile> {
        self.open_locked_wait(exclusive, true)?
            .ok_or_else(|| invalid_data("shared-record: lock unexpectedly unavailable"))
    }

    fn open_locked_wait(&self, exclusive: bool, wait: bool) -> std::io::Result<Option<LockedFile>> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{}", self.fd))?;
        // Check identity before locking/writing anything: a
        // guest may have replaced the inherited number with a
        // descriptor for an unrelated file.
        if file_identity(&file)? != self.identity {
            return Err(invalid_data("shared-record: file identity mismatch"));
        }
        if lock_file(&file, exclusive, wait)? {
            Ok(Some(LockedFile { file }))
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    fn try_lock_exclusive_for_test(&self) -> std::io::Result<Option<LockedFile>> {
        self.open_locked_wait(true, false)
    }

    pub fn snapshot(&self) -> std::io::Result<SharedRecord> {
        self.open_locked(false)?.read_snapshot()
    }

    pub fn replace(&self, record: &SharedRecord) -> std::io::Result<()> {
        self.open_locked(true)?.write_snapshot(record)
    }

    pub fn publish(&self, record: ProcessRecord) -> std::io::Result<()> {
        let locked = self.open_locked(true)?;
        let mut snapshot = locked.read_snapshot()?;
        snapshot
            .publish(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        locked.write_snapshot(&snapshot)
    }

    pub fn publish_exec_state(&self, id: ProcessId, state: &ExecState) -> std::io::Result<()> {
        let row = ProcessRecord::from_exec_state(id, state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        self.publish(row)
    }

    pub fn lookup(&self, id: ProcessId) -> std::io::Result<Option<ProcessRecord>> {
        Ok(self.snapshot()?.lookup(id).cloned())
    }

    pub fn remove(&self, id: ProcessId) -> std::io::Result<bool> {
        let locked = self.open_locked(true)?;
        let mut snapshot = locked.read_snapshot()?;
        let removed = snapshot.remove(id);
        if removed {
            locked.write_snapshot(&snapshot)?;
        }
        Ok(removed)
    }

    pub fn uts(&self) -> std::io::Result<UtsPair> {
        let snapshot = self.snapshot()?;
        Ok((snapshot.uts_nodename, snapshot.uts_domainname))
    }

    pub fn set_uts_nodename(&self, name: Option<Vec<u8>>) -> std::io::Result<()> {
        let locked = self.open_locked(true)?;
        let mut snapshot = locked.read_snapshot()?;
        snapshot
            .set_uts_nodename(name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        locked.write_snapshot(&snapshot)
    }

    pub fn set_uts_domainname(&self, name: Option<Vec<u8>>) -> std::io::Result<()> {
        let locked = self.open_locked(true)?;
        let mut snapshot = locked.read_snapshot()?;
        snapshot
            .set_uts_domainname(name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        locked.write_snapshot(&snapshot)
    }
}

static SHARED_RECORD_FILE: OnceLock<Option<SharedRecordFile>> = OnceLock::new();

/// Register the launcher-created store in the launcher/tracer
/// process. Returns false if a store was already registered.
pub fn init_shared_record_file(store: SharedRecordFile) -> bool {
    SHARED_RECORD_FILE.set(Some(store)).is_ok()
}

/// The registered store, or the inherited env-named store in a
/// successor process. Initialization captures the descriptor's
/// file identity before ordinary guest execution; later close,
/// replacement, or environment loss yields `None` on the next
/// store call (or no store at all), never a guessed descriptor.
pub fn shared_record_file() -> Option<&'static SharedRecordFile> {
    SHARED_RECORD_FILE
        .get_or_init(SharedRecordFile::from_env)
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: i32, start_time: u64, exe: &[u8]) -> ProcessRecord {
        ProcessRecord {
            id: ProcessId { pid, start_time },
            exe_guest: exe.to_vec(),
            argv: vec![exe.to_vec(), b"-x".to_vec()],
        }
    }

    fn sample() -> SharedRecord {
        SharedRecord {
            uts_nodename: Some(b"guest-a".to_vec()),
            uts_domainname: Some(Vec::new()),
            processes: vec![row(42, 900, b"/bin/sh"), row(7, 100, b"/bin/cat")],
        }
    }

    fn uts_wire(flags: u16, fields: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }

    #[test]
    fn unsorted_rows_are_found_and_publish_does_not_duplicate() {
        let mut record = sample();
        let id = ProcessId::new(42, 900).unwrap();
        assert_eq!(
            record.lookup(id).map(|row| row.exe_guest.as_slice()),
            Some(b"/bin/sh".as_slice())
        );
        record
            .publish(row(42, 900, b"/bin/updated"))
            .expect("replace row");
        assert_eq!(record.processes.len(), 2);
        assert_eq!(record.processes[0].id.pid, 7);
        assert_eq!(record.processes[1].id.pid, 42);
        assert_eq!(record.lookup(id).unwrap().exe_guest, b"/bin/updated");
    }

    #[test]
    fn roundtrip_canonicalizes_process_order() {
        let record = sample();
        let bytes = record.encode().expect("encode shared record");
        assert_eq!(&bytes[0..4], MAGIC);
        let back = SharedRecord::decode(&bytes).expect("decode shared record");
        assert_eq!(back.processes[0].id.pid, 7);
        assert_eq!(back.processes[1].id.pid, 42);
        assert_eq!(back.encode().expect("re-encode"), bytes);
    }

    #[test]
    fn empty_and_unset_fields_stay_distinct() {
        let back = SharedRecord::decode(&SharedRecord::new().encode().expect("encode empty"))
            .expect("decode empty");
        assert_eq!(back.uts_nodename, None);
        assert_eq!(back.uts_domainname, None);
        let sample = sample();
        let back =
            SharedRecord::decode(&sample.encode().expect("encode sample")).expect("decode sample");
        assert_eq!(back.uts_domainname, Some(Vec::new()));
    }

    #[test]
    fn pid_reuse_is_a_distinct_row() {
        let mut record = SharedRecord::new();
        record.publish(row(42, 100, b"/bin/old")).expect("old row");
        record.publish(row(42, 200, b"/bin/new")).expect("new row");
        assert_eq!(record.processes.len(), 2);
        assert_eq!(
            record
                .lookup(ProcessId::new(42, 100).unwrap())
                .unwrap()
                .exe_guest,
            b"/bin/old"
        );
        assert_eq!(
            record
                .lookup(ProcessId::new(42, 200).unwrap())
                .unwrap()
                .exe_guest,
            b"/bin/new"
        );
        record
            .publish(row(42, 100, b"/bin/updated"))
            .expect("replace exact identity");
        assert_eq!(record.processes.len(), 2);
        assert!(record.remove(ProcessId::new(42, 100).unwrap()));
        assert!(!record.remove(ProcessId::new(42, 100).unwrap()));
    }

    #[test]
    fn bootstrap_publishes_only_own_exec_state() {
        let state = ExecState {
            cwd: b"/work".to_vec(),
            exe_guest: b"/bin/sh".to_vec(),
            argv: vec![b"sh".to_vec()],
            ..Default::default()
        };
        let id = ProcessId::new(99, 1234).unwrap();
        let record = SharedRecord::bootstrap_from_exec_state(id, &state).expect("bootstrap");
        assert_eq!(record.uts_nodename, None);
        assert_eq!(record.lookup(id).unwrap().argv, vec![b"sh".to_vec()]);
    }

    #[test]
    fn decode_rejects_malformed_and_oversized_records() {
        let bytes = sample().encode().expect("encode");
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            SharedRecord::decode(&bad_magic),
            Err(SharedRecordError::BadMagic)
        );
        let mut bad_version = bytes.clone();
        bad_version[4] = 2;
        assert_eq!(
            SharedRecord::decode(&bad_version),
            Err(SharedRecordError::UnsupportedVersion(2))
        );
        assert_eq!(
            SharedRecord::decode(&bytes[..bytes.len() - 1]),
            Err(SharedRecordError::Truncated)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            SharedRecord::decode(&trailing),
            Err(SharedRecordError::TrailingBytes)
        );
        assert_eq!(
            SharedRecord::decode(&vec![0; MAX_ENCODED_BYTES + 1]),
            Err(SharedRecordError::TooLarge)
        );
    }

    #[test]
    fn decode_rejects_truncation_inside_fixed_width_fields() {
        let bytes = sample().encode().expect("encode");
        // Version and flags are fixed-width fields before any count.
        assert_eq!(
            SharedRecord::decode(&bytes[..5]),
            Err(SharedRecordError::Truncated)
        );
        assert_eq!(
            SharedRecord::decode(&bytes[..7]),
            Err(SharedRecordError::Truncated)
        );
        // Two-row layout here is header 8 + UTS fields 15 + count 4;
        // first sorted row is 46 bytes. Offset 79 lands two bytes into
        // the second row's start_time, past the aggregate row guard.
        assert_eq!(
            SharedRecord::decode(&bytes[..79]),
            Err(SharedRecordError::Truncated)
        );
    }

    #[test]
    fn decode_rejects_versions_and_unknown_flags() {
        let bytes = sample().encode().expect("encode");
        for version in [0u16, 3] {
            let mut v = bytes.clone();
            v[4..6].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                SharedRecord::decode(&v),
                Err(SharedRecordError::UnsupportedVersion(version))
            );
        }
        let mut unknown = bytes;
        unknown[6] |= 0x04;
        assert_eq!(
            SharedRecord::decode(&unknown),
            Err(SharedRecordError::Malformed)
        );
    }

    #[test]
    fn decode_each_single_uts_field_from_hand_wire() {
        let node = SharedRecord::decode(&uts_wire(1, &[b"node"])).expect("node only");
        assert_eq!(node.uts_nodename.as_deref(), Some(b"node".as_slice()));
        assert_eq!(node.uts_domainname, None);
        let domain = SharedRecord::decode(&uts_wire(2, &[b"dom"])).expect("domain only");
        assert_eq!(domain.uts_nodename, None);
        assert_eq!(domain.uts_domainname.as_deref(), Some(b"dom".as_slice()));
        let too_long = vec![b'x'; MAX_UTS_BYTES + 1];
        assert_eq!(
            SharedRecord::decode(&uts_wire(1, &[&too_long])),
            Err(SharedRecordError::InvalidUtsLength)
        );
    }

    #[test]
    fn decode_rejects_process_count_over_cap_before_row_truncation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&((MAX_PROCESSES + 1) as u32).to_le_bytes());
        assert_eq!(
            SharedRecord::decode(&bytes),
            Err(SharedRecordError::TooManyProcesses)
        );
    }

    #[test]
    fn from_parts_canonicalizes_and_validates_rows_and_uts() {
        let record = SharedRecord::from_parts(
            None,
            None,
            vec![row(42, 900, b"/bin/sh"), row(7, 100, b"/bin/cat")],
        )
        .expect("canonical bulk construction");
        assert_eq!(
            record
                .processes()
                .iter()
                .map(|row| row.id.pid)
                .collect::<Vec<_>>(),
            vec![7, 42]
        );
        assert_eq!(
            SharedRecord::from_parts(None, None, vec![row(1, 1, b"/bin/a"), row(1, 1, b"/bin/b")],),
            Err(SharedRecordError::UnsortedOrDuplicateProcess)
        );
        assert_eq!(
            SharedRecord::from_parts(Some(vec![b'x'; MAX_UTS_BYTES + 1]), None, Vec::new()),
            Err(SharedRecordError::InvalidUtsLength)
        );
    }

    #[test]
    fn remove_finds_row_in_unsorted_record() {
        let mut record = sample();
        let id = ProcessId::new(42, 900).unwrap();
        assert!(record.remove(id));
        assert_eq!(
            record
                .processes()
                .iter()
                .map(|row| row.id.pid)
                .collect::<Vec<_>>(),
            vec![7]
        );
        assert!(!record.remove(id));
    }

    #[test]
    fn encode_roundtrips_each_single_uts_field_with_exact_flag_byte() {
        for (record, flags) in [
            (
                SharedRecord::from_parts(Some(b"node".to_vec()), None, Vec::new()).unwrap(),
                FLAG_HAS_NODENAME,
            ),
            (
                SharedRecord::from_parts(None, Some(b"dom".to_vec()), Vec::new()).unwrap(),
                FLAG_HAS_DOMAINNAME,
            ),
        ] {
            let bytes = record.encode().expect("encode one UTS field");
            assert_eq!(
                u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
                flags,
                "encoded UTS flags"
            );
            assert_eq!(SharedRecord::decode(&bytes), Ok(record));
        }
    }

    #[test]
    fn process_cap_is_enforced_by_publish_and_encode_validation() {
        let mut record = SharedRecord {
            processes: (1..=MAX_PROCESSES as i32)
                .map(|pid| row(pid, 1, b"/bin/x"))
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            record.publish(row(MAX_PROCESSES as i32 + 1, 1, b"/bin/x")),
            Err(SharedRecordError::TooManyProcesses)
        );
        record
            .processes
            .push(row(MAX_PROCESSES as i32 + 1, 1, b"/bin/x"));
        assert_eq!(record.encode(), Err(SharedRecordError::TooManyProcesses));
    }

    #[test]
    fn encode_rejects_snapshot_over_size_cap() {
        let mut record = SharedRecord::new();
        let mut big = row(1, 1, b"/bin/big");
        big.argv = vec![vec![b'x'; MAX_ENCODED_BYTES]];
        record
            .publish(big)
            .expect("publish itself has no byte-size cap");
        assert_eq!(record.encode(), Err(SharedRecordError::TooLarge));
    }

    #[test]
    fn file_store_is_visible_across_handles_and_rejects_replaced_fd() {
        let first = SharedRecordFile::create().expect("create shared-record memfd");
        let second = SharedRecordFile {
            fd: first.fd(),
            identity: first.identity,
        };
        first.publish(row(42, 900, b"/bin/sh")).expect("publish");
        first
            .set_uts_nodename(Some(b"guest-a".to_vec()))
            .expect("set UTS");
        assert_eq!(
            second
                .lookup(ProcessId::new(42, 900).unwrap())
                .expect("lookup"),
            Some(row(42, 900, b"/bin/sh"))
        );
        assert_eq!(
            second.uts().expect("read UTS"),
            (Some(b"guest-a".to_vec()), None)
        );
        assert!(second
            .remove(ProcessId::new(42, 900).unwrap())
            .expect("remove"));
        assert_eq!(
            first
                .lookup(ProcessId::new(42, 900).unwrap())
                .expect("lookup removed"),
            None
        );

        let unrelated = SharedRecordFile::create().expect("create unrelated memfd");
        let replaced = SharedRecordFile {
            fd: unrelated.fd(),
            identity: first.identity,
        };
        assert_eq!(
            replaced
                .snapshot()
                .expect_err("replaced fd must fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        // The handles intentionally do not own/close the raw fd;
        // dropping them keeps both memfds for the test process.
    }

    #[test]
    fn file_store_adoption_rejects_missing_malformed_and_closed_env_fd() {
        assert!(SharedRecordFile::from_env_value(None).is_none());
        assert!(SharedRecordFile::from_env_value(Some("not-a-fd")).is_none());
        assert!(SharedRecordFile::from_env_value(Some("-1")).is_none());

        let store = SharedRecordFile::create().expect("create shared-record memfd");
        store.publish(row(42, 900, b"/bin/sh")).expect("publish");
        let adopted = SharedRecordFile::from_env_value(Some(&store.fd().to_string()))
            .expect("adopt valid env fd");
        assert_eq!(
            adopted
                .lookup(ProcessId::new(42, 900).unwrap())
                .expect("lookup adopted"),
            Some(row(42, 900, b"/bin/sh"))
        );

        // A descriptor that is open but is not a framed snapshot
        // is absent, never a partially trusted store.
        let null = std::fs::File::open("/dev/null").expect("open /dev/null");
        assert!(SharedRecordFile::from_env_value(Some(&null.as_raw_fd().to_string())).is_none());

        // Allocate the closed-fd probe above the ordinary
        // lowest-free range so another parallel test's ordinary
        // open does not immediately reuse this exact number.
        let mut closed = unsafe { libc::fcntl(store.fd(), libc::F_DUPFD_CLOEXEC, 512) };
        if closed < 0 {
            closed = unsafe { libc::dup(store.fd()) };
        }
        assert!(
            closed >= 0,
            "dup closed-fd probe: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(unsafe { libc::close(closed) }, 0);
        assert!(SharedRecordFile::from_env_value(Some(&closed.to_string())).is_none());
    }

    #[test]
    fn file_store_fails_closed_after_guest_dup2_and_close_range() {
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        store.publish(row(42, 900, b"/bin/sh")).expect("publish");
        let adopted_fd = unsafe { libc::dup(store.fd()) };
        assert!(
            adopted_fd >= 0,
            "dup adopted fd: {}",
            std::io::Error::last_os_error()
        );
        let adopted = SharedRecordFile {
            fd: adopted_fd,
            identity: store.identity,
        };
        assert_eq!(
            adopted
                .lookup(ProcessId::new(42, 900).unwrap())
                .expect("lookup before guest fd ops"),
            Some(row(42, 900, b"/bin/sh"))
        );

        let unrelated = SharedRecordFile::create().expect("create unrelated memfd");
        assert_eq!(
            unsafe { libc::dup2(unrelated.fd(), adopted_fd) },
            adopted_fd
        );
        assert_eq!(
            adopted
                .snapshot()
                .expect_err("dup2 replacement must fail closed")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            adopted
                .publish(row(43, 901, b"/bin/evil"))
                .expect_err("publish through replaced fd must fail closed")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            unrelated.snapshot().expect("unrelated snapshot"),
            SharedRecord::new()
        );

        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                adopted_fd as libc::c_uint,
                adopted_fd as libc::c_uint,
                0 as libc::c_uint,
            )
        };
        assert_eq!(
            rc,
            0,
            "close_range adopted fd: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            adopted.snapshot().is_err(),
            "closed adopted fd must be unavailable"
        );
    }

    #[test]
    fn ofd_lock_survives_closing_unrelated_fd_for_same_memfd() {
        use std::sync::mpsc;

        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let raw_fd = store.fd();
        let identity = store.identity;
        let (locked_tx, locked_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let guard = store
                .try_lock_exclusive_for_test()
                .expect("try lock")
                .expect("initial OFD lock is free");
            locked_tx.send(()).expect("report lock held");
            release_rx.recv().expect("wait for release");
            drop(guard);
        });
        locked_rx.recv().expect("holder reports lock");

        let unrelated = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{raw_fd}"))
            .expect("open unrelated description");
        drop(unrelated);

        let contender = SharedRecordFile {
            fd: raw_fd,
            identity,
        };
        assert!(
            contender
                .try_lock_exclusive_for_test()
                .expect("contender try lock")
                .is_none(),
            "OFD lock must survive closing an unrelated descriptor"
        );
        release_tx.send(()).expect("release holder");
        holder.join().expect("holder thread");
        assert!(contender
            .try_lock_exclusive_for_test()
            .expect("retake lock")
            .is_some());
    }

    #[test]
    fn file_store_accepts_exact_snapshot_cap_and_rejects_one_byte_over() {
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let mut record = SharedRecord::new();
        let mut row = row(1, 1, b"/bin/big");
        row.argv = vec![Vec::new()];
        record.publish(row.clone()).expect("publish boundary row");
        let overhead = record.encode().expect("encode boundary base").len();
        row.argv[0] = vec![b'x'; MAX_ENCODED_BYTES - overhead];
        record.publish(row.clone()).expect("publish exact cap row");
        assert_eq!(
            record.encode().expect("encode exact cap").len(),
            MAX_ENCODED_BYTES
        );
        store.replace(&record).expect("store exact cap snapshot");
        assert_eq!(store.snapshot().expect("load exact cap"), record);

        row.argv[0].push(b'x');
        let mut too_big = SharedRecord::new();
        too_big
            .publish(row)
            .expect("publish itself has no aggregate cap");
        let err = store.replace(&too_big).expect_err("cap+1 must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(store.snapshot().expect("previous snapshot remains"), record);
    }

    #[test]
    fn file_store_rejects_oversized_frame_without_rewriting_previous_snapshot() {
        use std::os::unix::fs::FileExt;

        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let good = sample();
        store.replace(&good).expect("store good snapshot");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{}", store.fd()))
            .expect("reopen memfd");
        file.write_all_at(&((MAX_ENCODED_BYTES + 1) as u64).to_le_bytes(), 0)
            .expect("write oversized frame header");
        let err = store.snapshot().expect_err("oversized frame must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn validation_rejects_bad_identities_paths_and_uts() {
        assert_eq!(
            ProcessId::new(0, 1),
            Err(SharedRecordError::InvalidProcessId)
        );
        let mut record = SharedRecord::new();
        assert_eq!(
            record.publish(row(1, 1, b"relative/sh")),
            Err(SharedRecordError::RelativePath)
        );
        assert_eq!(
            record.set_uts_nodename(Some(vec![b'x'; MAX_UTS_BYTES + 1])),
            Err(SharedRecordError::InvalidUtsLength)
        );
        let duplicate = SharedRecord {
            processes: vec![row(1, 1, b"/bin/a"), row(1, 1, b"/bin/b")],
            ..Default::default()
        };
        assert_eq!(
            duplicate.encode(),
            Err(SharedRecordError::UnsortedOrDuplicateProcess)
        );
    }
}
