# Stage-1b acceptance witnesses (for the gate side's S2)

Consumer-side witness list from literoot: the gate side's successor
arming (S2, convergence-plan engine) is judged against these.
Scope/interface: docs/stage1b-scope.md. All witnesses run the
*same* literoot Tool on in-guest vs ptrace and require
byte-identical stdout/stderr/exit code (mechanism-swap oracle,
design §9 comparator 3), plus the stated functional result.

## W1 — sh chain (execve successor arming)

```
literoot --backend liteinst -r <glibc rootfs> -w /work \
  /bin/sh -c 'export PATH=/bin:/usr/bin; pwd; cat hello.txt; ls /bin; /bin/cat /etc/os-release'
```
Pass: identical output to `--backend ptrace`; today:
`cat: Operation not supported` (EOPNOTSUPP at guest execve).
Covers: fork+exec from sh, PATH exec search, script-free ELF
exec through the rootfs PT_INTERP, cwd after exec.

## W2 — package manager (exec storms + scripts)

Alpine 3.21.3 minirootfs (sha256
1a694899e406ce55d32334c47ac0b2efb6c06d7e878102d1840892ad44cd5239):
```
literoot --backend liteinst -R <alpine> -0 /bin/sh -c \
  'apk add --no-network /root/zlib-1.3.2-r1.apk /root/libmagic-5.46-r2.apk /root/file-5.46-r2.apk; file /bin/busybox'
```
Pass: stdout identical to ptrace run; resulting tree
byte-identical to the proot run (already true on ptrace).
Covers: hundreds of execve (apk, busybox applets, trigger
scripts via shebang), musl PT_INTERP route, trigger-script
argv. If the musl loader-as-program route (scope §1.2b) is
not admitted, W2 may be substituted by the glibc-fixture
equivalent *only* with the refusal named in the run output.

## W3 — statloop8 (thread clone arming)

8-thread stat guest (literoot benchmark fixture) under
`--backend liteinst`: completes with correct count
(ok=40000), or refuses thread creation with a typed
EOPNOTSUPP the guest can observe — never SIGSEGV, never
untranslated escape (byte-count assertions catch both).
Today: SIGSEGV (139) / worker threads escape translation.

## W4 — failed-exec atomicity

Upstream `test-execve-eacces-enoexec` under `--backend
liteinst` (static binary): EACCES then ENOEXEC, guest stack
intact. (On ptrace this is the backend-fidelity case in
docs/execve-eacces-evidence.md; S2 must not inherit it.)

## Non-goals for S2 acceptance

Setuid successor arming beyond refusal-by-name, AT_EMPTY_PATH
execveat, and Wine-preloader-shaped address spaces (design
§13.3) are follow-ons, not S2 gates.
