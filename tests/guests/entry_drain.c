#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One line on fd 1 through a raw write: no stdio, so no fstat. */
static void say(const char *s) { syscall(SYS_write, 1, s, strlen(s)); }
static void on_signal(int sig) { (void)sig; }

/* C5 entry drain: a refused call, then one subscribed raw getuid (the
 * next Tool callback, where the reporter drains), then the guest creates
 * the marker file argv[1] and blocks reading fd 0 until the witness
 * closes it. The marker, not stdout, tells the witness the guest is
 * blocked: the liteinst launcher relays the guest's stdout only after
 * the guest exits. */
int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    char line[64];
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
        snprintf(line, sizeof line, "sigaction-refused errno=%d\n", errno);
    else
        snprintf(line, sizeof line, "sigaction-ok\n");
    say(line);
    syscall(SYS_getuid);
    say("blocked\n");
    if (argc > 1) {
        int fd = (int)syscall(SYS_openat, AT_FDCWD, argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0)
            syscall(SYS_close, fd);
    }
    char c;
    while (syscall(SYS_read, 0, &c, 1) > 0) {
    }
    return 7;
}
