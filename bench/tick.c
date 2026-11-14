// Append one byte to a file and exit: the child the fork+exec cell runs.
//
// usage: tick <counter-file>
//
// Each run appends "x" with O_APPEND, so after N runs the file holds N
// bytes and the parent can count its children without tracing them.
#include "bench.h"

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: tick <counter-file>\n");
    return 2;
  }
  int fd = open(argv[1], O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0) {
    perror("tick: open");
    return 2;
  }
  int ok = write(fd, "x", 1) == 1;
  if (close(fd) != 0) {
    ok = 0;
  }
  return ok ? 0 : 1;
}
