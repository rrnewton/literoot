// openat/close or readlink one path N times and report the time per call.
//
// usage: opsloop open <count> <path> [<expected-content>]
//        opsloop readlink <count> <path> <expected-target>
//
// Prints "count=<successful ops> ns_per_op=<n>". An open counts only when
// its close also succeeds; a readlink only when the bytes read equal
// <expected-target>. With <expected-content>, the opened file must also
// hold exactly that text plus a newline (checked once, after the timed
// loop). Exits 0 only if every check passed.
#include "bench.h"

int main(int argc, char **argv) {
  int is_open = (argc == 4 || argc == 5) && strcmp(argv[1], "open") == 0;
  int is_readlink = argc == 5 && strcmp(argv[1], "readlink") == 0;
  long n;
  if (!is_open && !is_readlink) {
    fprintf(stderr,
            "usage: opsloop open <count> <path> [<expected-content>] | readlink <count> <path> <expected>\n");
    return 2;
  }
  if (!parse_long(argv[2], 1, 1000000000L, &n)) {
    fprintf(stderr, "opsloop: bad count\n");
    return 2;
  }
  const char *path = argv[3];
  const char *want = is_readlink ? argv[4] : NULL;
  size_t want_len = want ? strlen(want) : 0;
  char buf[4096];
  long ok = 0;
  long long a = now_ns();
  for (long i = 0; i < n; i++) {
    if (is_open) {
      int fd = openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
      if (fd >= 0 && close(fd) == 0) {
        ok++;
      }
    } else {
      ssize_t len = readlink(path, buf, sizeof buf);
      if (len == (ssize_t)want_len && memcmp(buf, want, want_len) == 0) {
        ok++;
      }
    }
  }
  long long total = now_ns() - a;
  int checked = is_open && argc == 5;
  int content = !checked || content_is(path, argv[4]);
  printf("count=%ld ns_per_op=%lld%s\n", ok, total / n, !checked ? "" : content ? " content=ok" : " content=WRONG");
  return ok == n && content ? 0 : 1;
}
