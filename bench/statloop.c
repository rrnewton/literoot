// stat one path N times and report the time per call.
//
// usage: statloop <count> <path> [<expected-content>]
//
// Prints "count=<successful stats> ns_per_op=<n>" and exits 0 only if
// every stat succeeded. With <expected-content>, the file must also hold
// exactly that text plus a newline (checked once, after the timed loop),
// so a stat that reached a host file of the same name cannot pass.
#include <sys/stat.h>

#include "bench.h"

int main(int argc, char **argv) {
  long n;
  if (argc != 3 && argc != 4) {
    fprintf(stderr, "usage: statloop <count> <path> [<expected-content>]\n");
    return 2;
  }
  if (!parse_long(argv[1], 1, 1000000000L, &n)) {
    fprintf(stderr, "statloop: bad count\n");
    return 2;
  }
  struct stat st;
  long ok = 0;
  long long a = now_ns();
  for (long i = 0; i < n; i++) {
    if (stat(argv[2], &st) == 0) {
      ok++;
    }
  }
  long long total = now_ns() - a;
  int content = argc == 3 || content_is(argv[2], argv[3]);
  printf("count=%ld ns_per_op=%lld%s\n", ok, total / n, argc == 3 ? "" : content ? " content=ok" : " content=WRONG");
  return ok == n && content ? 0 : 1;
}
