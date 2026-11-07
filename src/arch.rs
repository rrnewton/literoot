//! The one home for literoot's per-architecture kernel ABI facts.
//!
//! `struct stat` layout differs between x86-64 (dev, ino, nlink,
//! mode, uid, gid) and the generic aarch64 layout (dev, ino, mode,
//! nlink, uid, gid); every offset into a guest stat/statx buffer in
//! rootfs_tool goes through these constants instead of literals.
//! `struct statx` is one UAPI layout on both architectures.

/// Offset of `st_mode` in the kernel `struct stat` buffer.
#[cfg(target_arch = "x86_64")]
pub const STAT_MODE_OFF: usize = 24;
/// Offset of `st_mode` in the kernel `struct stat` buffer.
#[cfg(target_arch = "aarch64")]
pub const STAT_MODE_OFF: usize = 16;
/// Offset of `st_uid` in the kernel `struct stat` buffer.
#[cfg(target_arch = "x86_64")]
pub const STAT_UID_OFF: usize = 28;
/// Offset of `st_uid` in the kernel `struct stat` buffer.
#[cfg(target_arch = "aarch64")]
pub const STAT_UID_OFF: usize = 24;
/// Offset of `st_gid` in the kernel `struct stat` buffer.
#[cfg(target_arch = "x86_64")]
pub const STAT_GID_OFF: usize = 32;
/// Offset of `st_gid` in the kernel `struct stat` buffer.
#[cfg(target_arch = "aarch64")]
pub const STAT_GID_OFF: usize = 28;

/// Offset of `stx_mode` in the kernel `struct statx` buffer (all arches).
pub const STATX_MODE_OFF: usize = 28;
/// Offset of `stx_uid` in the kernel `struct statx` buffer (all arches).
pub const STATX_UID_OFF: usize = 20;
/// Offset of `stx_gid` in the kernel `struct statx` buffer (all arches).
pub const STATX_GID_OFF: usize = 24;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("literoot supports x86_64 and aarch64 only");
