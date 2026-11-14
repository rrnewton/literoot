// Run one command and record its wall time and its CPU time.
//
// usage: timeit <out.json> <cmd> [args...]
//
// Writes one JSON object to <out.json>: the command's exit status, the
// wall time from CLOCK_MONOTONIC around fork+exec+wait, and the child's
// user/system time and peak RSS from wait4's rusage (see README.md for
// what those cover). <out.json> is created or truncated. The command's
// stdin, stdout and stderr are inherited. timeit exits with the
// command's status (128+signal for a signal).
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long ns(const struct timespec *t) {
  return (long long)t->tv_sec * 1000000000LL + t->tv_nsec;
}

static long long tv_ns(const struct timeval *t) {
  return (long long)t->tv_sec * 1000000000LL + (long long)t->tv_usec * 1000LL;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: timeit <out.json> <cmd> [args...]\n");
    return 2;
  }
  struct timespec start, end;
  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
    perror("timeit: clock_gettime");
    return 2;
  }
  pid_t pid = fork();
  if (pid < 0) {
    perror("timeit: fork");
    return 2;
  }
  if (pid == 0) {
    execvp(argv[2], argv + 2);
    fprintf(stderr, "timeit: exec %s: %s\n", argv[2], strerror(errno));
    _exit(127);
  }
  int status = 0;
  struct rusage ru;
  while (wait4(pid, &status, 0, &ru) < 0) {
    if (errno != EINTR) {
      perror("timeit: wait4");
      return 2;
    }
  }
  if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
    perror("timeit: clock_gettime");
    return 2;
  }
  int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  FILE *out = fopen(argv[1], "w");
  if (!out) {
    perror("timeit: open output");
    return 2;
  }
  fprintf(out,
          "{\"rc\":%d,\"wall_ns\":%lld,\"utime_ns\":%lld,\"stime_ns\":%lld,"
          "\"maxrss_kb\":%ld}\n",
          code, ns(&end) - ns(&start), tv_ns(&ru.ru_utime), tv_ns(&ru.ru_stime),
          ru.ru_maxrss);
  if (fclose(out) != 0) {
    perror("timeit: write output");
    return 2;
  }
  return code;
}
