#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* One line on fd 1 through a raw write: no stdio, so no fstat. */
static void say(const char *s) { syscall(SYS_write, 1, s, strlen(s)); }

static void report(const char *what, long rc, int err) {
    char line[96];
    if (rc < 0)
        snprintf(line, sizeof line, "%s-refused errno=%d\n", what, err);
    else
        snprintf(line, sizeof line, "%s-ok\n", what);
    say(line);
}

/* A child, when the call is allowed (the ptrace control), exits at once. */
static void reap(long pid) {
    if (pid == 0) syscall(SYS_exit_group, 0);
    if (pid > 0) waitpid((pid_t)pid, NULL, 0);
}

static void on_signal(int sig) { (void)sig; }
static void *thread_body(void *arg) { return arg; }

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *mode = argv[1];
    long rc;
    if (!strcmp(mode, "fork")) {            /* W10: glibc fork() is clone without CLONE_THREAD */
        rc = fork(); int e = errno; reap(rc); report("fork", rc, e);
    } else if (!strcmp(mode, "raw-fork")) { /* W10: syscall(SYS_fork) */
        rc = syscall(SYS_fork); int e = errno; reap(rc); report("raw-fork", rc, e);
    } else if (!strcmp(mode, "fork-then-exit")) {
        /* W10x: after fork() the only syscalls are a raw write and
         * exit_group, so only the exit drain can name the refusal. */
        rc = fork(); int e = errno; reap(rc); report("fork", rc, e);
        syscall(SYS_exit_group, 7);
    } else if (!strcmp(mode, "sigaction")) { /* W11 */
        struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_signal;
        rc = sigaction(SIGUSR1, &sa, NULL); report("sigaction", rc, errno);
    } else if (!strcmp(mode, "sigaltstack")) { /* W11, second case */
        static char stack[1 << 16];
        stack_t ss = { .ss_sp = stack, .ss_size = sizeof stack, .ss_flags = 0 };
        rc = sigaltstack(&ss, NULL); report("sigaltstack", rc, errno);
    } else if (!strcmp(mode, "thread")) {    /* W12 */
        pthread_t t; int r = pthread_create(&t, NULL, thread_body, NULL);
        if (r == 0) pthread_join(t, NULL);
        report("thread", r == 0 ? 0 : -1, r);
    } else {
        return 2;
    }
    return 7;
}
