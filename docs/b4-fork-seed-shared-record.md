# B4 fork seed and shared-record codec slice

## Status and dependency

This slice is stacked only on B4-1's reviewed head
(`41e790a`, containing canonical `ExecState` at `15840f4`).
B4-1 admission is still pending, so this slice deliberately
contains no syscall subscriptions, no Tool dispatch changes,
no successor/exec-stop/loader wiring, and absolutely no
arming of `exec_watch`. It is a design plus pure codec layer
that later fork and transport work can call without changing
either wire format casually.

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
  restore contract learns to carry that bit; a pre-bootstrap
  parent would skip the launcher-exec transition, and the
  fork-wiring slice must refuse that case by name rather than
  use this seed silently.
- The fork seed is the value a later step stages before a
  process-creating clone and applies in the child's fresh
  Tool before ordinary execution. Thread clones must not use
  the seed. The later fork-wiring slice owns clone-family
  classification, parent cleanup, and any suite re-baselining.

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

## Transport direction (not wired here)

The snapshot bytes are an exchange/bootstrap form, not a
proposed in-place shared-memory layout. A future transport
may carry this snapshot once at admission, or translate its
rows into an inherited-memfd directory following the probe
generation precedent. Either way, these semantics are fixed
now:

1. A process publishes only its own qualified row after its
   `ExecState` has been restored (or at initial launch from
   an equivalent current-image capture).
2. Lookups for another process must match both pid and start
   time; failure to find that qualified row is absence, not
   permission to fall back to a bare-pid row.
3. UTS writes replace the shared field as one value; they
   are never snapshotted into `ExecState`, because a sibling
   update after fork/exec must remain visible.
4. Reaping/removal, the start-time source, locking or atomic
   row publication, sealing, and who creates any memfd are
   transport-slice questions. They must be answered there;
   this codec does not pretend a copied snapshot stays live.

The exec transports likewise remain as designed for B4:
native W6a carries `ExecState` in the sealed thread-state
slot, while exec-stop and any future loader must deliver the
same bytes before the successor's first post-exec operation
or refuse the stateful exec by name. No transport gets a
second per-process state format.

## Non-goals and next slices

- No fork syscall interception or child Tool application is
  wired in this slice; it only proves the fork-seed capture
  semantics and encoding.
- No shared memory, file, socket, RPC, or supervisor state
  is introduced.
- No PID/UTS consumers switch from today's ptrace-process
  statics to `SharedRecord` yet.
- No `exec_watch` arming and no dependency on P1-P3.

Next slices can therefore be reviewed independently: fork
wiring consuming `capture_fork_seed`, then a transport that
instantiates or imports `SharedRecord`, then switching
`PID_EXE`/`PID_ARGV`/UTS readers and writers to it with the
existing ptrace suite as the non-regression anchor.
