# B4 fork seed and shared record

## Status and dependency

This document records the B4 stack in order: the codec
slice on B4-1's reviewed head (`41e790a`, containing
canonical `ExecState` at `15840f4`), the fork-wiring slice
that stages and applies those seeds, and the first
shared-record transport and consumers below. The stack
adds no successor/exec-stop/loader format and absolutely
no arming of `exec_watch`; later transport work must not
change either wire format casually.

## Fork seed

`ExecState` remains the one per-process continuity payload
for both exec and fork. The slice does not invent a second
fork encoding.

- `capture` remains the exec-boundary operation: the exec
  handler first stages the successor's `exe_guest`/argv, then
  captures.
- `capture_fork_seed` is the clone-boundary operation: it
  captures the parent's current image from values the caller
  obtained from its own accessors (`RootfsTool::exe_guest`
  and the same materialized argv used by the cmdline path).
  The codec does not resolve `initial_exe` itself, so
  launch-cwd-relative translation/reverse normalization and
  the empty-`initial_exe` fallback cannot drift into a
  second implementation in the seed path.
- Capture still copies fake identity exactly and never
  initializes it. `apply_to` remains the sole restore path:
  validation happens before mutation, `bootstrapped` becomes
  true, and scratch is not carried. Consequently a fork seed
  may only be staged for a bootstrapped parent until the
  restore contract learns to carry that bit; for a
  pre-bootstrap parent, staging is refused by name and the
  clone proceeds unstaged rather than applying a seed that
  would skip the launcher-exec transition.
- The fork seed is the value the current process-creating
  clone handlers stage before a clone for the existing step-4
  machinery to apply in the child's fresh Tool before
  ordinary execution. Thread clones must not use the seed.

Current Tool wiring is intentionally narrow: process-
creating Clone/Clone3/Fork/Vfork handlers compute the
accessor-produced current exe/argv before taking the capture
lock, refuse to stage for an unbootstrapped parent by name
(the clone proceeds unstaged), and otherwise stage the fork
seed in the existing pending slot. The already-landed
step-4 pending clone into `init_thread_state`, parent clear
after inject, and `handle_thread_start` application are
unchanged; this slice only replaces how the staged fork
snapshot is captured. See "First shared-record transport"
below for the now-wired publication/consumption slice.

## Shared-record snapshot

`SharedRecord` holds only facts visible across processes:

- optional UTS nodename/domainname, each at most 64 bytes;
- a process directory keyed by `(pid, start_time)`, with each
  row containing that process's guest exe path and argv.

It does **not** contain cwd, fd/path maps, root override,
fake identity, dirent progress, or launch config. Those are
either per-process `ExecState` state or immutable config
re-delivered by the backend.

`publish_exec_state` derives a process's own row from its
restored `ExecState`. A reused numeric pid is safe only when
paired with its start time: equal pid + equal start time is
the same row; equal pid with a new start time is a different
row and never overwrites the predecessor.

The `LRS1` snapshot encoding is versioned, canonical
(process rows sorted by qualified identity), strict on
decode, and capped at 1 MiB / 4096 process rows. It carries
no pointers, host VAs, config bytes, ordering timestamps,
or synchronization metadata. The row vector is private and
only bulk construction (`from_parts`), publication, removal,
and decode can populate it, each restoring or requiring the
sorted invariant before binary search is used. Publication
has no per-row byte cap: an oversized row may exist in
memory while snapshot encoding refuses the whole record
`TooLarge`; it is never truncated or automatically reaped,
so a bootstrap transport must surface or resolve that named
refusal itself.

## First shared-record transport

`SharedRecordFile` is the first transport. The launcher
creates one memfd, initializes it with an empty snapshot,
registers it for Tools hosted in the launcher process, and
passes its number through `LITEROOT_SHARED_RECORD_FD`
following the existing probe-generation fd precedent. The
file holds one whole length-framed snapshot, not an
in-place shared-memory layout. The snapshot payload cap is
`MAX_ENCODED_BYTES` = 1 MiB (plus the 8-byte frame header,
so a 1,048,584-byte file at most), with at most 4096
process rows. Each operation reopens `/proc/self/fd/<fd>`
so it locks a distinct open file description with Linux
OFD locks, then reloads or rewrites the bounded snapshot
while holding that lock. The exact 1 MiB payload is stored;
one byte over refuses without replacing the previous
snapshot.

The handle records `(st_dev, st_ino)` when created/adopted
and validates the reopened file before locking or writing.
The descriptor it checks is the one in the process hosting
the Tool. In an in-guest process that is also the guest's
descriptor table: if guest code closes the inherited
number, `dup2`s another file over it, closes it through
close_range, or scrubs the environment before exec, there
is no guessed descriptor, record operations are
unavailable, and each consumer retains today's
process-local behavior. Under ptrace the Tool's descriptor
is in the tracer, so a guest closing its own inherited copy
does not disable the tracer's consumers. In every backend,
a guest that deliberately writes through its copy can
still corrupt the framed snapshot; strict decoding makes
consumers fail closed to their process-local fallbacks. The
inherited
probe-generation descriptor is narrower: `translate.rs`
already falls back when its env is scrubbed or the fd was
closed before first use, and after the first-use mmap the
fd number no longer matters. It does not identity-check a
replacement made before that mmap; that is follow-up
`dh-n6pie`, not part of this slice.

Publication is from the Tool's current accessor-materialized
exe/argv and is keyed by the host `/proc/<pid>/stat` start
time. It happens after a fork-seed restore in
`handle_thread_start` and after each successful post-exec
transition. Other-process synthetic `/proc/<pid>/exe` and
cmdline lookups consult the shared row first, then today's
detached bare-pid maps. UTS setters write both today's
statics and the shared fields; the uname reader prefers a
shared field when present and otherwise retains that
field's existing static, so a refused shared write does not
erase the process-local value. There is intentionally
no process-exit reaping hook in this slice: qualified
identities make stale rows non-aliasing, while removal, a
sealed/atomic in-place layout, and permission hardening are
later transport work.

## Transport direction (later slices)

The snapshot bytes remain an exchange/bootstrap form, not a
proposed in-place shared-memory layout. A future transport
may carry this snapshot once at admission, or translate its
rows into an inherited-memfd directory following the probe
generation precedent. Either way, these semantics are fixed
now:

1. A process publishes only its own qualified row after its
   `ExecState` has been restored (or at initial launch from
   an equivalent current-image capture).
2. Lookups for another process must match both pid and start
   time; failure to find that qualified row is absence from
   `SharedRecord`, never permission to match a bare-pid row
   inside it. The first consumers retain today's separate
   bare-pid maps as a transitional fallback when the store
   or qualified row is unavailable; removing that fallback
   after publication covers clone windows is later work.
3. UTS writes replace the shared field as one value; they
   are never snapshotted into `ExecState`, because a sibling
   update after fork/exec must remain visible.
4. The first transport answers the start-time source
   (`/proc/<pid>/stat`), OFD locking, and launcher memfd
   creation above. Reaping/removal, an atomic in-place row
   layout, and sealing remain later transport work; this
   codec does not pretend a copied snapshot stays live.

The exec transports likewise remain as designed for B4:
native W6a carries `ExecState` in the sealed thread-state
slot, while exec-stop and any future loader must deliver the
same bytes before the successor's first post-exec operation
or refuse the stateful exec by name. No transport gets a
second per-process state format.

## Non-goals and next slices

- No process-exit reaping, sealed file, atomic in-place
  layout, or guest-fd virtualization is introduced; the
  whole-snapshot memfd and fail-closed identity checks are
  the first transport only.
- The transitional bare-pid map and UTS-static fallbacks
  remain where named above, rather than being deleted in
  the same slice that first publishes shared rows.
- No `exec_watch` arming and no dependency on P1-P3.

Next slices can therefore be reviewed independently:
reaping and permission hardening, publication that closes
clone windows so the bare-pid fallback can be removed, and
any atomic in-place layout that replaces whole-snapshot
rewrites.
