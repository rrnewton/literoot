// Small helpers shared by the bench programs.
#ifndef BENCH_H
#define BENCH_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// parse_long: a whole decimal argument in [lo, hi], or 0 on anything else.
static inline int parse_long(const char *s, long lo, long hi, long *out) {
  char *end;
  errno = 0;
  long v = strtol(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi) {
    return 0;
  }
  *out = v;
  return 1;
}

// now_ns: CLOCK_MONOTONIC in nanoseconds; exits 2 if the clock fails.
static inline long long now_ns(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) {
    perror("clock_gettime");
    exit(2);
  }
  return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

// content_is: 1 if the file at <path> holds exactly <want> plus a newline.
// The rootfs fixtures hold known text, so a read that reached a file of
// the same name outside the rootfs fails this check.
static inline int content_is(const char *path, const char *want) {
  char buf[256];
  size_t len = strlen(want);
  if (len + 1 >= sizeof buf) {
    return 0;
  }
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t got = read(fd, buf, sizeof buf);
  close(fd);
  return got == (ssize_t)(len + 1) && memcmp(buf, want, len) == 0 && buf[len] == '\n';
}

#endif
