// stat one path from T threads, N times each.
//
// usage: threadstat <threads> <count-per-thread> <path> [<expected-content>]
//
// Prints "count=<successful stats> threads=<T>" and exits 0 only if
// every stat in every thread succeeded. Point <path> at a file that
// exists only inside the rootfs: a thread whose stats escape to the
// host then fails them, and the run fails instead of looking fast. With
// <expected-content>, every thread also reads the file once after its
// loop and must find exactly that text plus a newline.
#include <pthread.h>
#include <sys/stat.h>

#include "bench.h"

struct job {
  const char *path;
  const char *want;
  long n;
  long ok;
  int content_ok;
};

static void *worker(void *arg) {
  struct job *job = arg;
  struct stat st;
  long ok = 0;
  // Count in a local and store once: per-op stores into adjacent jobs
  // would share cache lines between threads and add a cost of their own.
  for (long i = 0; i < job->n; i++) {
    if (stat(job->path, &st) == 0) {
      ok++;
    }
  }
  job->ok = ok;
  job->content_ok = !job->want || content_is(job->path, job->want);
  return NULL;
}

int main(int argc, char **argv) {
  long t, n;
  if (argc != 4 && argc != 5) {
    fprintf(stderr, "usage: threadstat <threads> <count-per-thread> <path> [<expected-content>]\n");
    return 2;
  }
  if (!parse_long(argv[1], 1, 256, &t) || !parse_long(argv[2], 1, 1000000000L, &n)) {
    fprintf(stderr, "threadstat: bad arguments\n");
    return 2;
  }
  pthread_t tid[256];
  struct job jobs[256];
  for (long i = 0; i < t; i++) {
    jobs[i] = (struct job){argv[3], argc == 5 ? argv[4] : NULL, n, 0, 0};
    if (pthread_create(&tid[i], NULL, worker, &jobs[i]) != 0) {
      fprintf(stderr, "threadstat: pthread_create failed\n");
      return 2;
    }
  }
  long ok = 0, content_ok = 0;
  for (long i = 0; i < t; i++) {
    pthread_join(tid[i], NULL);
    ok += jobs[i].ok;
    content_ok += jobs[i].content_ok;
  }
  printf("count=%ld threads=%ld%s\n", ok, t,
         argc == 4 ? "" : content_ok == t ? " content=ok" : " content=WRONG");
  return ok == t * n && content_ok == t ? 0 : 1;
}
