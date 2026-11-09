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
use std::sync::{Mutex, OnceLock};

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

/// Error from a file-backed shared-record write. When the
/// refusal was counted in the shared frame header while the
/// write held the exclusive lock, `refusal_count` carries
/// that session-wide count back to the reporting call site.
#[derive(Debug)]
pub struct StoreError {
    source: std::io::Error,
    refusal_count: Option<u64>,
}

impl StoreError {
    fn new(source: std::io::Error) -> Self {
        Self {
            source,
            refusal_count: None,
        }
    }

    fn with_refusal_count(source: std::io::Error, refusal_count: u64) -> Self {
        Self {
            source,
            refusal_count: Some(refusal_count),
        }
    }

    pub fn kind(&self) -> std::io::ErrorKind {
        self.source.kind()
    }

    pub fn refusal_count(&self) -> Option<u64> {
        self.refusal_count
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(source: std::io::Error) -> Self {
        Self::new(source)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

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

const FRAME_MAGIC: &[u8; 4] = b"LRSF";
const FRAME_VERSION: u16 = 2;
const FRAME_HEADER_BYTES: usize = 40;
const FRAME_V1_HEADER_BYTES: usize = 8;

/// A shared-record write category whose refusals are counted
/// in the frame header for the whole guest session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCategory {
    Publish,
    UtsNodename,
    UtsDomainname,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FrameMeta {
    publish_refusals: u64,
    nodename_refusals: u64,
    domainname_refusals: u64,
}

impl FrameMeta {
    fn increment(&mut self, category: RefusalCategory) -> u64 {
        let count = match category {
            RefusalCategory::Publish => &mut self.publish_refusals,
            RefusalCategory::UtsNodename => &mut self.nodename_refusals,
            RefusalCategory::UtsDomainname => &mut self.domainname_refusals,
        };
        *count = count.saturating_add(1);
        *count
    }
}

struct Frame {
    record: SharedRecord,
    meta: FrameMeta,
    header_len: usize,
    payload_len: usize,
}

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

const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const LOCK_INITIAL_RETRY: std::time::Duration = std::time::Duration::from_millis(1);
const LOCK_MAX_RETRY: std::time::Duration = std::time::Duration::from_millis(10);

fn try_lock_file(file: &File, exclusive: bool) -> std::io::Result<bool> {
    let mut request: libc::flock = unsafe { std::mem::zeroed() };
    request.l_type = (if exclusive {
        libc::F_WRLCK
    } else {
        libc::F_RDLCK
    }) as i16;
    request.l_whence = libc::SEEK_SET as i16;
    // SAFETY: `request` is a fully initialized flock for the
    // whole file; the descriptor remains open in `file`.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &request) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if matches!(err.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EACCES)) {
        return Ok(false);
    }
    Err(err)
}

struct LockedFile {
    file: File,
}

impl LockedFile {
    fn read_frame(&self) -> std::io::Result<Frame> {
        use std::os::unix::fs::FileExt;

        let len = self.file.metadata()?.len();
        if len < FRAME_V1_HEADER_BYTES as u64 {
            return Err(invalid_data("shared-record: short frame header"));
        }
        if len > (FRAME_HEADER_BYTES + MAX_ENCODED_BYTES) as u64 {
            return Err(invalid_data("shared-record: frame exceeds snapshot cap"));
        }
        let mut prefix = [0u8; FRAME_V1_HEADER_BYTES];
        self.file.read_exact_at(&mut prefix, 0)?;
        let (header_len, payload_len, meta) = if &prefix[..4] == FRAME_MAGIC.as_slice() {
            if len < FRAME_HEADER_BYTES as u64 {
                return Err(invalid_data("shared-record: short frame header"));
            }
            let mut header = [0u8; FRAME_HEADER_BYTES];
            self.file.read_exact_at(&mut header, 0)?;
            let version = u16::from_le_bytes(header[4..6].try_into().unwrap());
            let declared_header_len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
            if version != FRAME_VERSION || declared_header_len != FRAME_HEADER_BYTES {
                return Err(invalid_data("shared-record: unsupported frame header"));
            }
            (
                FRAME_HEADER_BYTES,
                u64::from_le_bytes(header[8..16].try_into().unwrap()),
                FrameMeta {
                    publish_refusals: u64::from_le_bytes(header[16..24].try_into().unwrap()),
                    nodename_refusals: u64::from_le_bytes(header[24..32].try_into().unwrap()),
                    domainname_refusals: u64::from_le_bytes(header[32..40].try_into().unwrap()),
                },
            )
        } else {
            (
                FRAME_V1_HEADER_BYTES,
                u64::from_le_bytes(prefix),
                FrameMeta::default(),
            )
        };
        if payload_len > MAX_ENCODED_BYTES as u64 {
            return Err(invalid_data("shared-record: snapshot payload over cap"));
        }
        if len != header_len as u64 + payload_len {
            return Err(invalid_data("shared-record: frame length mismatch"));
        }
        let mut payload = vec![0u8; payload_len as usize];
        self.file.read_exact_at(&mut payload, header_len as u64)?;
        let record = SharedRecord::decode(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Frame {
            record,
            meta,
            header_len,
            payload_len: payload_len as usize,
        })
    }

    fn read_snapshot(&self) -> std::io::Result<SharedRecord> {
        Ok(self.read_frame()?.record)
    }

    fn read_meta_or_default(&self) -> FrameMeta {
        self.read_frame()
            .map(|frame| frame.meta)
            .unwrap_or_default()
    }

    fn frame_header(payload_len: usize, meta: FrameMeta) -> [u8; FRAME_HEADER_BYTES] {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        header[..4].copy_from_slice(FRAME_MAGIC);
        header[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&(FRAME_HEADER_BYTES as u16).to_le_bytes());
        header[8..16].copy_from_slice(&(payload_len as u64).to_le_bytes());
        header[16..24].copy_from_slice(&meta.publish_refusals.to_le_bytes());
        header[24..32].copy_from_slice(&meta.nodename_refusals.to_le_bytes());
        header[32..40].copy_from_slice(&meta.domainname_refusals.to_le_bytes());
        header
    }

    fn write_frame(&self, record: &SharedRecord, meta: FrameMeta) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;

        let payload = record
            .encode()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut framed = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        framed.extend_from_slice(&Self::frame_header(payload.len(), meta));
        framed.extend_from_slice(&payload);
        self.file.write_all_at(&framed, 0)?;
        self.file.set_len(framed.len() as u64)
    }

    fn write_meta(&self, meta: FrameMeta, payload_len: usize) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;

        self.file
            .write_all_at(&Self::frame_header(payload_len, meta), 0)
    }

    fn write_snapshot(&self, record: &SharedRecord) -> std::io::Result<()> {
        let meta = self.read_meta_or_default();
        self.write_frame(record, meta)
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

/// What a deferred repair may remove: only the exact stale
/// value this handle last saw (`Compare`), or nothing at all
/// in the shared snapshot (`LocalOnly`, when this handle had
/// never observed the store before its write timed out).
#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingGuard<T> {
    Compare(T),
    LocalOnly,
}

/// Repairs owed after a write could not acquire the lock.
/// A guarded repair removes a value only if the snapshot
/// still holds the exact stale value this handle last saw,
/// so it cannot erase a newer write by another process (or
/// by a parent whose state a fork child inherited).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PendingRepairs {
    nodename: Option<PendingGuard<Option<Vec<u8>>>>,
    domainname: Option<PendingGuard<Option<Vec<u8>>>>,
    rows: std::collections::BTreeMap<ProcessId, PendingGuard<Option<ProcessRecord>>>,
}

impl PendingRepairs {
    fn is_empty(&self) -> bool {
        self.nodename.is_none() && self.domainname.is_none() && self.rows.is_empty()
    }

    fn merge(&mut self, other: PendingRepairs) {
        if self.nodename.is_none() {
            self.nodename = other.nodename;
        }
        if self.domainname.is_none() {
            self.domainname = other.domainname;
        }
        for (id, guard) in other.rows {
            self.rows.entry(id).or_insert(guard);
        }
    }

    /// Apply only the guarded repairs whose expected stale
    /// value is still present. Returns whether the snapshot
    /// changed. `LocalOnly` repairs never mutate it.
    fn apply_to(&self, snapshot: &mut SharedRecord) -> bool {
        let mut changed = false;
        if let Some(PendingGuard::Compare(expected)) = &self.nodename {
            if &snapshot.uts_nodename == expected && snapshot.uts_nodename.is_some() {
                snapshot.uts_nodename = None;
                changed = true;
            }
        }
        if let Some(PendingGuard::Compare(expected)) = &self.domainname {
            if &snapshot.uts_domainname == expected && snapshot.uts_domainname.is_some() {
                snapshot.uts_domainname = None;
                changed = true;
            }
        }
        for (id, guard) in &self.rows {
            if let PendingGuard::Compare(expected) = guard {
                if snapshot.lookup(*id) == expected.as_ref() && expected.is_some() {
                    snapshot.remove(*id);
                    changed = true;
                }
            }
        }
        changed
    }
}

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
    pending: Mutex<PendingRepairs>,
    last_snapshot: Mutex<Option<SharedRecord>>,
}

impl SharedRecordFile {
    fn from_fd_identity(fd: RawFd, identity: FileIdentity) -> Self {
        Self {
            fd,
            identity,
            pending: Mutex::new(PendingRepairs::default()),
            last_snapshot: Mutex::new(None),
        }
    }

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
        let store = Self::from_fd_identity(fd, identity);
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
        let store = Self::from_fd_identity(fd, identity_of_fd(fd).ok()?);
        // Establishing the expected file's identity is part of
        // adoption: a malformed or replaced descriptor is
        // absent, not a partially trusted store.
        store.snapshot().ok()?;
        Some(store)
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Keep this handle usable in the current (tracer) process
    /// while ensuring a spawned guest does not inherit a copy.
    pub fn set_close_on_exec(&self) -> std::io::Result<()> {
        // SAFETY: F_GETFD/F_SETFD only inspect and update this
        // descriptor's flags; ownership is unchanged.
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let rc = unsafe { libc::fcntl(self.fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn open_locked(&self, exclusive: bool) -> std::io::Result<LockedFile> {
        self.open_locked_timeout(exclusive, LOCK_TIMEOUT)
    }

    fn open_locked_timeout(
        &self,
        exclusive: bool,
        timeout: std::time::Duration,
    ) -> std::io::Result<LockedFile> {
        // Never park in F_OFD_SETLKW. Under a deterministic
        // ptrace scheduler the lock holder may need this
        // process to yield/sleep before it can run and release
        // the lock; a kernel lock wait can therefore deadlock
        // the guest tree. Reopen and revalidate on every try,
        // then yield and sleep with bounded exponential delay.
        let deadline = std::time::Instant::now() + timeout;
        let mut delay = LOCK_INITIAL_RETRY;
        loop {
            if let Some(locked) = self.open_locked_try(exclusive)? {
                return Ok(locked);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "shared-record: lock contention timeout",
                ));
            }
            std::thread::yield_now();
            std::thread::sleep(delay.min(deadline - now));
            delay = (delay * 2).min(LOCK_MAX_RETRY);
        }
    }

    fn open_locked_try(&self, exclusive: bool) -> std::io::Result<Option<LockedFile>> {
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
        if try_lock_file(&file, exclusive)? {
            Ok(Some(LockedFile { file }))
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    fn try_lock_exclusive_for_test(&self) -> std::io::Result<Option<LockedFile>> {
        self.open_locked_try(true)
    }

    fn remember_snapshot(&self, snapshot: &SharedRecord) {
        *self.last_snapshot.lock().unwrap() = Some(snapshot.clone());
    }

    fn pending_row_guard(&self, id: ProcessId) -> PendingGuard<Option<ProcessRecord>> {
        match &*self.last_snapshot.lock().unwrap() {
            Some(snapshot) => PendingGuard::Compare(snapshot.lookup(id).cloned()),
            None => PendingGuard::LocalOnly,
        }
    }

    fn pending_nodename_guard(&self) -> PendingGuard<Option<Vec<u8>>> {
        match &*self.last_snapshot.lock().unwrap() {
            Some(snapshot) => PendingGuard::Compare(snapshot.uts_nodename.clone()),
            None => PendingGuard::LocalOnly,
        }
    }

    fn pending_domainname_guard(&self) -> PendingGuard<Option<Vec<u8>>> {
        match &*self.last_snapshot.lock().unwrap() {
            Some(snapshot) => PendingGuard::Compare(snapshot.uts_domainname.clone()),
            None => PendingGuard::LocalOnly,
        }
    }

    fn note_pending_row(&self, id: ProcessId) {
        let guard = self.pending_row_guard(id);
        self.pending.lock().unwrap().rows.entry(id).or_insert(guard);
    }

    fn note_pending_nodename(&self) {
        let guard = self.pending_nodename_guard();
        let mut pending = self.pending.lock().unwrap();
        if pending.nodename.is_none() {
            pending.nodename = Some(guard);
        }
    }

    fn note_pending_domainname(&self) {
        let guard = self.pending_domainname_guard();
        let mut pending = self.pending.lock().unwrap();
        if pending.domainname.is_none() {
            pending.domainname = Some(guard);
        }
    }

    fn pending_repairs(&self) -> PendingRepairs {
        self.pending.lock().unwrap().clone()
    }

    /// Drop the `Compare` entries in `applied` (they were
    /// either persisted or superseded by a newer value).
    /// `LocalOnly` entries stay until their own field/row is
    /// successfully written.
    fn forget_compare_pending(&self, applied: &PendingRepairs) {
        let mut pending = self.pending.lock().unwrap();
        if matches!(applied.nodename, Some(PendingGuard::Compare(_)))
            && pending.nodename == applied.nodename
        {
            pending.nodename = None;
        }
        if matches!(applied.domainname, Some(PendingGuard::Compare(_)))
            && pending.domainname == applied.domainname
        {
            pending.domainname = None;
        }
        for (id, guard) in &applied.rows {
            if matches!(guard, PendingGuard::Compare(_)) && pending.rows.get(id) == Some(guard) {
                pending.rows.remove(id);
            }
        }
    }

    fn clear_pending_row(&self, id: ProcessId) {
        self.pending.lock().unwrap().rows.remove(&id);
    }

    fn clear_pending_nodename(&self) {
        self.pending.lock().unwrap().nodename = None;
    }

    fn clear_pending_domainname(&self) {
        self.pending.lock().unwrap().domainname = None;
    }

    fn try_apply_pending_repairs(&self) {
        let repairs = self.pending_repairs();
        if repairs.is_empty() {
            return;
        }
        let Ok(Some(locked)) = self.open_locked_try(true) else {
            return;
        };
        let Ok(mut snapshot) = locked.read_snapshot() else {
            return;
        };
        self.remember_snapshot(&snapshot);
        if !repairs.apply_to(&mut snapshot) {
            // Every guarded repair was superseded (or is
            // local-only); forget the superseded guards.
            self.forget_compare_pending(&repairs);
            return;
        }
        if locked.write_snapshot(&snapshot).is_ok() {
            self.remember_snapshot(&snapshot);
            self.forget_compare_pending(&repairs);
        }
    }

    pub fn snapshot(&self) -> std::io::Result<SharedRecord> {
        let snapshot = self.open_locked(false)?.read_snapshot()?;
        self.remember_snapshot(&snapshot);
        Ok(snapshot)
    }

    pub fn replace(&self, record: &SharedRecord) -> std::io::Result<()> {
        let locked = self.open_locked(true)?;
        locked.write_snapshot(record)?;
        *self.pending.lock().unwrap() = PendingRepairs::default();
        self.remember_snapshot(record);
        Ok(())
    }

    pub fn publish(&self, record: ProcessRecord) -> StoreResult<()> {
        self.publish_with_timeout(record, LOCK_TIMEOUT)
    }

    fn publish_with_timeout(
        &self,
        record: ProcessRecord,
        timeout: std::time::Duration,
    ) -> StoreResult<()> {
        let id = record.id;
        let locked = match self.open_locked_timeout(true, timeout) {
            Ok(locked) => locked,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    self.note_pending_row(id);
                }
                return Err(err.into());
            }
        };
        let frame = locked.read_frame()?;
        let mut meta = frame.meta;
        let original_snapshot = frame.record.clone();
        let mut snapshot = frame.record;
        self.remember_snapshot(&snapshot);
        let repairs = self.pending_repairs();
        let repairs_changed = repairs.apply_to(&mut snapshot);
        if let Err(err) = snapshot.publish(record) {
            let err = std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string());
            let count = meta.increment(RefusalCategory::Publish);
            let removed = snapshot.remove(id);
            let cleanup_attempted = removed || repairs_changed;
            let persisted = if cleanup_attempted {
                locked.write_frame(&snapshot, meta).is_ok()
            } else if frame.header_len == FRAME_HEADER_BYTES {
                locked.write_meta(meta, frame.payload_len).is_ok()
            } else {
                locked.write_frame(&original_snapshot, meta).is_ok()
            };
            if persisted && cleanup_attempted {
                self.remember_snapshot(&snapshot);
                self.forget_compare_pending(&repairs);
                self.clear_pending_row(id);
            } else if cleanup_attempted {
                self.note_pending_row(id);
            }
            return Err(if persisted {
                StoreError::with_refusal_count(err, count)
            } else {
                err.into()
            });
        }
        if let Err(err) = locked.write_frame(&snapshot, meta) {
            // A refused replacement must not leave its stale
            // predecessor to outrank process-local state. This
            // snapshot is the previously valid one plus the
            // attempted replacement, so removing that row can
            // only shrink it back under the cap.
            let count = meta.increment(RefusalCategory::Publish);
            let cleanup_wrote = snapshot.remove(id) && locked.write_frame(&snapshot, meta).is_ok();
            if cleanup_wrote {
                self.remember_snapshot(&snapshot);
                self.forget_compare_pending(&repairs);
                self.clear_pending_row(id);
                return Err(StoreError::with_refusal_count(err, count));
            }
            self.note_pending_row(id);
            return Err(err.into());
        }
        self.remember_snapshot(&snapshot);
        self.forget_compare_pending(&repairs);
        self.clear_pending_row(id);
        Ok(())
    }

    pub fn publish_exec_state(&self, id: ProcessId, state: &ExecState) -> StoreResult<()> {
        let row = ProcessRecord::from_exec_state(id, state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        self.publish(row)
    }

    pub fn lookup(&self, id: ProcessId) -> std::io::Result<Option<ProcessRecord>> {
        self.try_apply_pending_repairs();
        let snapshot = self.snapshot()?;
        let pending = self.pending_repairs();
        if let Some(guard) = pending.rows.get(&id) {
            match guard {
                PendingGuard::Compare(expected) if snapshot.lookup(id) == expected.as_ref() => {
                    return Ok(None);
                }
                PendingGuard::Compare(_) => {}
                PendingGuard::LocalOnly => return Ok(None),
            }
        }
        Ok(snapshot.lookup(id).cloned())
    }

    pub fn remove(&self, id: ProcessId) -> std::io::Result<bool> {
        self.remove_with_timeout(id, LOCK_TIMEOUT)
    }

    fn remove_with_timeout(
        &self,
        id: ProcessId,
        timeout: std::time::Duration,
    ) -> std::io::Result<bool> {
        let locked = match self.open_locked_timeout(true, timeout) {
            Ok(locked) => locked,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    self.note_pending_row(id);
                }
                return Err(err);
            }
        };
        let mut snapshot = locked.read_snapshot()?;
        self.remember_snapshot(&snapshot);
        let repairs = self.pending_repairs();
        let had_row = snapshot.lookup(id).is_some();
        let repairs_changed = repairs.apply_to(&mut snapshot);
        let pending_removed = had_row && snapshot.lookup(id).is_none();
        let removed = snapshot.remove(id);
        if removed || repairs_changed {
            if let Err(err) = locked.write_snapshot(&snapshot) {
                if removed {
                    self.note_pending_row(id);
                }
                return Err(err);
            }
            self.remember_snapshot(&snapshot);
            self.forget_compare_pending(&repairs);
            self.clear_pending_row(id);
        }
        Ok(removed || pending_removed)
    }

    pub fn uts(&self) -> std::io::Result<UtsPair> {
        self.try_apply_pending_repairs();
        let snapshot = self.snapshot()?;
        let pending = self.pending_repairs();
        let nodename = match &pending.nodename {
            Some(PendingGuard::Compare(expected)) if &snapshot.uts_nodename == expected => None,
            Some(PendingGuard::LocalOnly) => None,
            _ => snapshot.uts_nodename.clone(),
        };
        let domainname = match &pending.domainname {
            Some(PendingGuard::Compare(expected)) if &snapshot.uts_domainname == expected => None,
            Some(PendingGuard::LocalOnly) => None,
            _ => snapshot.uts_domainname.clone(),
        };
        Ok((nodename, domainname))
    }

    pub fn set_uts_nodename(&self, name: Option<Vec<u8>>) -> StoreResult<()> {
        self.set_uts_nodename_with_timeout(name, LOCK_TIMEOUT)
    }

    fn set_uts_nodename_with_timeout(
        &self,
        name: Option<Vec<u8>>,
        timeout: std::time::Duration,
    ) -> StoreResult<()> {
        let locked = match self.open_locked_timeout(true, timeout) {
            Ok(locked) => locked,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    self.note_pending_nodename();
                }
                return Err(err.into());
            }
        };
        let frame = locked.read_frame()?;
        let mut meta = frame.meta;
        let original_snapshot = frame.record.clone();
        let mut snapshot = frame.record;
        self.remember_snapshot(&snapshot);
        let repairs = self.pending_repairs();
        let _repairs_changed = repairs.apply_to(&mut snapshot);
        if let Err(err) = snapshot.set_uts_nodename(name) {
            let err = std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string());
            let count = meta.increment(RefusalCategory::UtsNodename);
            let persisted = if frame.header_len == FRAME_HEADER_BYTES {
                locked.write_meta(meta, frame.payload_len).is_ok()
            } else {
                locked.write_frame(&original_snapshot, meta).is_ok()
            };
            return Err(if persisted {
                StoreError::with_refusal_count(err, count)
            } else {
                err.into()
            });
        }
        if let Err(err) = locked.write_frame(&snapshot, meta) {
            // Clearing the attempted field can only shrink the
            // previously valid snapshot, and prevents its stale
            // value from outranking the caller's local update.
            let count = meta.increment(RefusalCategory::UtsNodename);
            let cleanup_wrote = snapshot.set_uts_nodename(None).is_ok()
                && locked.write_frame(&snapshot, meta).is_ok();
            if cleanup_wrote {
                self.remember_snapshot(&snapshot);
                self.forget_compare_pending(&repairs);
                self.clear_pending_nodename();
                return Err(StoreError::with_refusal_count(err, count));
            }
            self.note_pending_nodename();
            return Err(err.into());
        }
        self.remember_snapshot(&snapshot);
        self.forget_compare_pending(&repairs);
        self.clear_pending_nodename();
        Ok(())
    }

    pub fn set_uts_domainname(&self, name: Option<Vec<u8>>) -> StoreResult<()> {
        self.set_uts_domainname_with_timeout(name, LOCK_TIMEOUT)
    }

    fn set_uts_domainname_with_timeout(
        &self,
        name: Option<Vec<u8>>,
        timeout: std::time::Duration,
    ) -> StoreResult<()> {
        let locked = match self.open_locked_timeout(true, timeout) {
            Ok(locked) => locked,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    self.note_pending_domainname();
                }
                return Err(err.into());
            }
        };
        let frame = locked.read_frame()?;
        let mut meta = frame.meta;
        let original_snapshot = frame.record.clone();
        let mut snapshot = frame.record;
        self.remember_snapshot(&snapshot);
        let repairs = self.pending_repairs();
        let _repairs_changed = repairs.apply_to(&mut snapshot);
        if let Err(err) = snapshot.set_uts_domainname(name) {
            let err = std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string());
            let count = meta.increment(RefusalCategory::UtsDomainname);
            let persisted = if frame.header_len == FRAME_HEADER_BYTES {
                locked.write_meta(meta, frame.payload_len).is_ok()
            } else {
                locked.write_frame(&original_snapshot, meta).is_ok()
            };
            return Err(if persisted {
                StoreError::with_refusal_count(err, count)
            } else {
                err.into()
            });
        }
        if let Err(err) = locked.write_frame(&snapshot, meta) {
            let count = meta.increment(RefusalCategory::UtsDomainname);
            let cleanup_wrote = snapshot.set_uts_domainname(None).is_ok()
                && locked.write_frame(&snapshot, meta).is_ok();
            if cleanup_wrote {
                self.remember_snapshot(&snapshot);
                self.forget_compare_pending(&repairs);
                self.clear_pending_domainname();
                return Err(StoreError::with_refusal_count(err, count));
            }
            self.note_pending_domainname();
            return Err(err.into());
        }
        self.remember_snapshot(&snapshot);
        self.forget_compare_pending(&repairs);
        self.clear_pending_domainname();
        Ok(())
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
        let second = SharedRecordFile::from_fd_identity(first.fd(), first.identity);
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
        let replaced = SharedRecordFile::from_fd_identity(unrelated.fd(), first.identity);
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
        let adopted = SharedRecordFile::from_fd_identity(adopted_fd, store.identity);
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

        let contender = SharedRecordFile::from_fd_identity(raw_fd, identity);
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
    fn lock_retry_is_bounded() {
        use std::sync::mpsc;

        assert_eq!(LOCK_TIMEOUT, std::time::Duration::from_secs(5));
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let guard = store
            .try_lock_exclusive_for_test()
            .expect("try lock")
            .expect("initial lock is free");
        let contender = SharedRecordFile::from_fd_identity(store.fd(), store.identity);
        let watched = SharedRecordFile::from_fd_identity(store.fd(), store.identity);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let kind = match watched.open_locked_timeout(true, std::time::Duration::from_millis(25))
            {
                Ok(_) => None,
                Err(err) => Some(err.kind()),
            };
            let _ = tx.send(kind);
        });
        let started = std::time::Instant::now();
        let kind = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("watchdog: bounded lock retry did not return");
        assert_eq!(kind, Some(std::io::ErrorKind::WouldBlock));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "bounded retry took {:?}",
            started.elapsed()
        );
        drop(guard);
        contender
            .open_locked_timeout(true, std::time::Duration::from_secs(1))
            .expect("lock after release");
    }

    #[test]
    fn lock_contention_child_helper() {
        use std::io::Write as _;

        let Some(raw) = std::env::var_os("LITEROOT_SHARED_RECORD_TEST_CHILD_FD") else {
            return;
        };
        let fd: RawFd = raw.to_string_lossy().parse().expect("child fd number");
        let store = SharedRecordFile::from_fd_identity(
            fd,
            identity_of_fd(fd).expect("child fstat inherited memfd"),
        );
        assert!(
            store
                .try_lock_exclusive_for_test()
                .expect("child try lock")
                .is_none(),
            "child process unexpectedly took the parent-held OFD lock"
        );
        println!("LOCK_BLOCKED");
        std::io::stdout().flush().expect("flush blocked marker");
        store
            .publish(row(4242, 777, b"/bin/child"))
            .expect("child publish after parent releases the lock");
        println!("LOCK_PUBLISHED");
        std::io::stdout().flush().expect("flush published marker");
    }

    #[test]
    fn lock_contention_between_processes_retries_until_release() {
        use std::io::{BufRead as _, BufReader};
        use std::process::{Command, Stdio};

        if std::env::var_os("LITEROOT_SHARED_RECORD_TEST_CHILD_FD").is_some() {
            return;
        }
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let guard = store
            .try_lock_exclusive_for_test()
            .expect("parent try lock")
            .expect("parent lock is free");
        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "shared_record::tests::lock_contention_child_helper",
                "--nocapture",
            ])
            .env(
                "LITEROOT_SHARED_RECORD_TEST_CHILD_FD",
                store.fd().to_string(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn lock-contention child test process");
        let stdout = child.stdout.take().expect("child stdout pipe");
        let mut lines = BufReader::new(stdout).lines();
        let mut saw_blocked = false;
        for line in lines.by_ref() {
            let line = line.expect("read child stdout");
            if line.contains("LOCK_BLOCKED") {
                saw_blocked = true;
                break;
            }
        }
        assert!(
            saw_blocked,
            "child did not report cross-process lock contention"
        );
        // Keep the lock through several retry intervals. The
        // child has already entered publish(); with no retry it
        // returns WouldBlock and fails before this release.
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(guard);

        let mut saw_published = false;
        for line in lines {
            let line = line.expect("read child stdout after release");
            if line.contains("LOCK_PUBLISHED") {
                saw_published = true;
            }
            // Drain to EOF so the child harness does not get
            // SIGPIPE while printing its own test result.
        }
        assert!(saw_published, "child did not publish after lock release");
        let status = child.wait().expect("wait for lock-contention child");
        assert!(status.success(), "child helper failed: {status}");
        assert_eq!(
            store
                .lookup(ProcessId::new(4242, 777).unwrap())
                .expect("lookup child row"),
            Some(row(4242, 777, b"/bin/child"))
        );
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
    fn file_store_rejects_oversized_frame_header() {
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
        assert!(
            err.to_string().contains("snapshot payload over cap"),
            "unexpected oversized-frame error: {err}"
        );
    }

    #[test]
    fn file_store_rejects_frame_length_mismatch() {
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        store.replace(&sample()).expect("store good snapshot");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{}", store.fd()))
            .expect("reopen memfd");
        let len = file.metadata().expect("frame length").len();
        file.set_len(len + 1).expect("append one unmatched byte");
        let err = store
            .snapshot()
            .expect_err("frame length mismatch must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("frame length mismatch"),
            "unexpected frame error: {err}"
        );
    }

    #[test]
    fn file_store_refused_uts_write_clears_stale_field() {
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let mut record =
            SharedRecord::from_parts(Some(b"first".to_vec()), Some(b"dom".to_vec()), Vec::new())
                .expect("record with UTS fields");
        let mut filler = row(1, 1, b"/bin/big");
        filler.argv = vec![Vec::new()];
        record.publish(filler.clone()).expect("publish filler base");
        let overhead = record.encode().expect("encode exact-cap base").len();
        filler.argv[0] = vec![b'x'; MAX_ENCODED_BYTES - overhead];
        record
            .publish(filler.clone())
            .expect("publish exact filler");
        assert_eq!(
            record.encode().expect("encode exact cap").len(),
            MAX_ENCODED_BYTES
        );
        store.replace(&record).expect("store exact cap");

        let err = store
            .set_uts_nodename(Some(b"second-longer-name".to_vec()))
            .expect_err("over-cap UTS replacement must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.refusal_count(), Some(1));
        assert_eq!(
            store.uts().expect("UTS after refusal"),
            (None, Some(b"dom".to_vec()))
        );
        assert_eq!(
            store
                .lookup(filler.id)
                .expect("lookup filler after UTS refusal"),
            Some(filler)
        );
    }

    #[test]
    fn file_store_refused_domainname_write_clears_stale_field() {
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let mut record = SharedRecord::from_parts(
            Some(b"node".to_vec()),
            Some(b"first-dom".to_vec()),
            Vec::new(),
        )
        .expect("record with UTS fields");
        let mut filler = row(1, 1, b"/bin/big");
        filler.argv = vec![Vec::new()];
        record.publish(filler.clone()).expect("publish filler base");
        let overhead = record.encode().expect("encode exact-cap base").len();
        filler.argv[0] = vec![b'x'; MAX_ENCODED_BYTES - overhead];
        record
            .publish(filler.clone())
            .expect("publish exact filler");
        assert_eq!(
            record.encode().expect("encode exact cap").len(),
            MAX_ENCODED_BYTES
        );
        store.replace(&record).expect("store exact cap");

        let err = store
            .set_uts_domainname(Some(b"second-longer-domain".to_vec()))
            .expect_err("over-cap domainname replacement must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.refusal_count(), Some(1));
        assert_eq!(
            store.uts().expect("UTS after domainname refusal"),
            (Some(b"node".to_vec()), None)
        );
        assert_eq!(
            store
                .lookup(filler.id)
                .expect("lookup filler after domainname refusal"),
            Some(filler)
        );
    }

    #[test]
    fn lock_timeout_pending_repairs_overlay_and_persist_on_next_write() {
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        store
            .set_uts_nodename(Some(b"first".to_vec()))
            .expect("set initial nodename");
        store
            .set_uts_domainname(Some(b"dom".to_vec()))
            .expect("set initial domainname");
        let target = row(4242, 777, b"/bin/old");
        store.publish(target.clone()).expect("publish initial row");

        // A shared lock lets later reads proceed while making
        // both writes below time out on the exclusive lock.
        let read_guard = store
            .open_locked_try(false)
            .expect("try shared lock")
            .expect("shared lock is free");
        let err = store
            .set_uts_nodename_with_timeout(
                Some(b"second".to_vec()),
                std::time::Duration::from_millis(25),
            )
            .expect_err("UTS write must time out under a held lock");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        let mut replacement = target.clone();
        replacement.exe_guest = b"/bin/new".to_vec();
        let err = store
            .publish_with_timeout(replacement, std::time::Duration::from_millis(25))
            .expect_err("publish must time out under a held lock");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

        // The raw snapshot is still stale, but this handle's
        // consumers must not let it outrank local state.
        assert_eq!(
            store
                .snapshot()
                .expect("raw snapshot before repair")
                .uts_nodename,
            Some(b"first".to_vec())
        );
        assert_eq!(
            store.uts().expect("UTS with pending repair"),
            (None, Some(b"dom".to_vec()))
        );
        assert_eq!(
            store.lookup(target.id).expect("lookup with pending repair"),
            None
        );
        drop(read_guard);

        // A later read opportunistically persists the repairs
        // when it can take the lock without waiting.
        assert_eq!(
            store.uts().expect("UTS read applying pending repairs"),
            (None, Some(b"dom".to_vec()))
        );
        let repaired = store.snapshot().expect("snapshot after read-side repair");
        assert_eq!(repaired.uts_nodename, None);
        assert_eq!(repaired.lookup(target.id), None);

        // The next successful write also persists both repairs.
        store
            .set_uts_domainname_with_timeout(
                Some(b"newdom".to_vec()),
                std::time::Duration::from_secs(1),
            )
            .expect("write that applies pending repairs");
        let snapshot = store.snapshot().expect("raw snapshot after repair");
        assert_eq!(snapshot.uts_nodename, None);
        assert_eq!(snapshot.uts_domainname, Some(b"newdom".to_vec()));
        assert_eq!(snapshot.lookup(target.id), None);
    }

    #[test]
    fn refusal_counts_are_shared_across_handles() {
        let first = SharedRecordFile::create().expect("create shared-record memfd");
        // Fill the snapshot exactly, with no UTS fields, so
        // every attempt to add one is a cap refusal counted
        // under the lock the refusing write already holds.
        let mut record = SharedRecord::new();
        let mut filler = row(1, 1, b"/bin/big");
        filler.argv = vec![Vec::new()];
        record.publish(filler.clone()).expect("publish filler base");
        let overhead = record.encode().expect("encode exact-cap base").len();
        filler.argv[0] = vec![b'x'; MAX_ENCODED_BYTES - overhead];
        record
            .publish(filler.clone())
            .expect("publish exact filler");
        first.replace(&record).expect("store exact cap");

        // A fresh handle adopted from the same descriptor
        // stands in for a new in-guest program image after
        // exec: its process-local state is new, but the frame
        // header counts are the session's.
        let second = SharedRecordFile::from_env_value(Some(&first.fd().to_string()))
            .expect("adopt same memfd in a fresh handle");
        let err = first
            .set_uts_nodename(Some(b"x".to_vec()))
            .expect_err("first nodename write must refuse at the cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.refusal_count(), Some(1));
        let err = second
            .set_uts_nodename(Some(b"y".to_vec()))
            .expect_err("second nodename write must refuse at the cap");
        assert_eq!(
            err.refusal_count(),
            Some(2),
            "a new image must not reset the session refusal count"
        );
        let err = second
            .set_uts_domainname(Some(b"d".to_vec()))
            .expect_err("domainname write must refuse at the cap");
        assert_eq!(
            err.refusal_count(),
            Some(1),
            "categories count independently"
        );
        let err = first
            .set_uts_domainname(Some(b"e".to_vec()))
            .expect_err("second domainname write must refuse at the cap");
        assert_eq!(err.refusal_count(), Some(2));
        assert_eq!(first.snapshot().expect("snapshot after counts"), record);
    }

    #[test]
    fn pending_repair_does_not_erase_newer_write_from_another_handle() {
        let a = SharedRecordFile::create().expect("create shared-record memfd");
        a.set_uts_nodename(Some(b"first".to_vec()))
            .expect("set initial nodename");
        a.set_uts_domainname(Some(b"dom".to_vec()))
            .expect("set initial domainname");
        let old = row(4242, 777, b"/bin/old");
        a.publish(old.clone()).expect("publish initial row");
        let b = SharedRecordFile::from_env_value(Some(&a.fd().to_string()))
            .expect("adopt same memfd as second handle");
        assert_eq!(
            b.uts().expect("second handle UTS").0,
            Some(b"first".to_vec())
        );

        let read_guard = a
            .open_locked_try(false)
            .expect("try shared lock")
            .expect("shared lock is free");
        let err = a
            .set_uts_nodename_with_timeout(
                Some(b"second".to_vec()),
                std::time::Duration::from_millis(25),
            )
            .expect_err("A UTS write must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        let err = a
            .set_uts_domainname_with_timeout(
                Some(b"second-dom".to_vec()),
                std::time::Duration::from_millis(25),
            )
            .expect_err("A domainname write must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        let mut a_replacement = old.clone();
        a_replacement.exe_guest = b"/bin/a-new".to_vec();
        let err = a
            .publish_with_timeout(a_replacement, std::time::Duration::from_millis(25))
            .expect_err("A publish must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        drop(read_guard);

        b.set_uts_nodename(Some(b"third".to_vec()))
            .expect("B writes a newer nodename");
        b.set_uts_domainname(Some(b"third-dom".to_vec()))
            .expect("B writes a newer domainname");
        let mut b_row = old.clone();
        b_row.exe_guest = b"/bin/b-new".to_vec();
        b.publish(b_row.clone()).expect("B publishes a newer row");

        assert_eq!(
            a.uts().expect("A reads after B writes"),
            (Some(b"third".to_vec()), Some(b"third-dom".to_vec())),
            "A's deferred clears must not erase B's newer UTS fields"
        );
        assert_eq!(
            a.lookup(old.id).expect("A looks up after B writes"),
            Some(b_row),
            "A's deferred removal must not erase B's newer row"
        );
        let raw = a.snapshot().expect("raw snapshot after guarded repairs");
        assert_eq!(raw.uts_nodename, Some(b"third".to_vec()));
        assert_eq!(raw.uts_domainname, Some(b"third-dom".to_vec()));
        assert_eq!(
            raw.lookup(old.id).map(|row| row.exe_guest.as_slice()),
            Some(b"/bin/b-new".as_slice())
        );
    }

    #[test]
    fn file_store_refused_publish_removes_stale_row() {
        let store = SharedRecordFile::create().expect("create shared-record memfd");
        let mut target = row(1, 1, b"/bin/target");
        target.argv = vec![b"target".to_vec()];
        let mut filler = row(2, 1, b"/bin/big");
        filler.argv = vec![Vec::new()];
        let mut record = SharedRecord::new();
        record.publish(target.clone()).expect("publish target base");
        record.publish(filler.clone()).expect("publish filler base");
        let overhead = record.encode().expect("encode exact-cap base").len();
        filler.argv[0] = vec![b'x'; MAX_ENCODED_BYTES - overhead];
        record
            .publish(filler.clone())
            .expect("publish exact filler");
        assert_eq!(
            record.encode().expect("encode exact cap").len(),
            MAX_ENCODED_BYTES
        );
        store.replace(&record).expect("store exact cap");

        let mut replacement = target.clone();
        replacement.argv[0].push(b'x');
        let err = store
            .publish(replacement)
            .expect_err("one-byte-larger replacement must refuse at the cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.refusal_count(), Some(1));
        assert_eq!(
            store.lookup(target.id).expect("lookup refused target"),
            None,
            "stale target row must be removed after a refused replacement"
        );
        assert_eq!(
            store
                .lookup(filler.id)
                .expect("lookup filler after refusal"),
            Some(filler.clone())
        );

        let mut invalid = filler.clone();
        invalid.exe_guest = b"relative/path".to_vec();
        let err = store
            .publish(invalid)
            .expect_err("invalid replacement must also refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.refusal_count(), Some(2));
        assert_eq!(
            store
                .lookup(filler.id)
                .expect("lookup invalidly replaced row"),
            None,
            "any refused replacement must leave no stale row"
        );
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
