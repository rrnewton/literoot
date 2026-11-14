// Open, read 4 KiB and close every file of a tree, from T threads.
//
// usage: walker <threads> <passes> <dir> <files> [<expected-first-line>]
//
// <dir> holds files f00000 .. f<files-1>, each 4096 bytes (see
// mktree.sh). The files are split between the threads; each thread
// makes <passes> passes over its share. Prints "bytes=<total read>
// files=<files> passes=<passes> threads=<T>" and exits 0 only if the
// total equals files * passes * 4096. A thread whose opens escape the
// rootfs reads nothing, so the run fails rather than looking fast. With
// <expected-first-line>, a read counts only if the file starts with that
// text and a newline, so a same-named file outside the rootfs does not
// count. Threads are created even for T = 1.
#include <pthread.h>

#include "bench.h"

struct job {
  const char *dir;
  const char *want;
  long first, end, passes;
  long long bytes;
};

static void *worker(void *arg) {
  struct job *job = arg;
  char path[4096];
  char buf[4096];
  size_t want_len = job->want ? strlen(job->want) : 0;
  long long bytes = 0;
  // Count in a local and store once (see threadstat.c).
  for (long p = 0; p < job->passes; p++) {
    for (long i = job->first; i < job->end; i++) {
      snprintf(path, sizeof path, "%s/f%05ld", job->dir, i);
      int fd = open(path, O_RDONLY | O_CLOEXEC);
      if (fd < 0) {
        continue;
      }
      ssize_t got = read(fd, buf, sizeof buf);
      close(fd);
      if (got <= 0) {
        continue;
      }
      if (job->want && ((size_t)got <= want_len || memcmp(buf, job->want, want_len) != 0 ||
                        buf[want_len] != '\n')) {
        continue;
      }
      bytes += got;
    }
  }
  job->bytes = bytes;
  return NULL;
}

int main(int argc, char **argv) {
  long t, passes, files;
  if (argc != 5 && argc != 6) {
    fprintf(stderr, "usage: walker <threads> <passes> <dir> <files> [<expected-first-line>]\n");
    return 2;
  }
  if (!parse_long(argv[1], 1, 64, &t) || !parse_long(argv[2], 1, 1000000, &passes) ||
      !parse_long(argv[4], 1, 99999, &files)) {
    fprintf(stderr, "walker: bad arguments\n");
    return 2;
  }
  pthread_t tid[64];
  struct job jobs[64];
  for (long i = 0; i < t; i++) {
    jobs[i] = (struct job){argv[3], argc == 6 ? argv[5] : NULL, files * i / t, files * (i + 1) / t,
                           passes, 0};
    if (pthread_create(&tid[i], NULL, worker, &jobs[i]) != 0) {
      fprintf(stderr, "walker: pthread_create failed\n");
      return 2;
    }
  }
  long long bytes = 0;
  for (long i = 0; i < t; i++) {
    pthread_join(tid[i], NULL);
    bytes += jobs[i].bytes;
  }
  printf("bytes=%lld files=%ld passes=%ld threads=%ld\n", bytes, files, passes, t);
  return bytes == (long long)files * passes * 4096 ? 0 : 1;
}
