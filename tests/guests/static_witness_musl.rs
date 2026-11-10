//! The static musl witness guest (W10, W12): no Rust runtime, so no
//! signal handlers or alternate stack are installed before main.
#![no_std]
#![no_main]

use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_long;
use core::ffi::c_void;

#[link(name = "c")]
extern "C" {
    fn fork() -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
    fn pthread_create(
        thread: *mut usize,
        attr: *const c_void,
        start: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn pthread_join(thread: usize, retval: *mut *mut c_void) -> c_int;
}

const SYS_WRITE: c_long = 1;
const SYS_FORK: c_long = 57;
const SYS_EXIT_GROUP: c_long = 231;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { syscall(SYS_EXIT_GROUP, 99 as c_long) };
    loop {}
}

fn say(bytes: &[u8]) {
    unsafe { syscall(SYS_WRITE, 1 as c_long, bytes.as_ptr(), bytes.len()) };
}

/// `<what>-ok` or `<what>-refused errno=<n>`, through one raw write.
fn report(what: &[u8], rc: c_long, err: c_int) {
    let mut line = [0u8; 64];
    let mut n = 0;
    let mut put = |b: &[u8]| {
        line[n..n + b.len()].copy_from_slice(b);
        n += b.len();
    };
    put(what);
    if rc < 0 {
        put(b"-refused errno=");
        let mut digits = [0u8; 10];
        let (mut d, mut v) = (digits.len(), err as u32);
        loop {
            d -= 1;
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        put(&digits[d..]);
    } else {
        put(b"-ok");
    }
    put(b"\n");
    say(&line[..n]);
}

fn reap(pid: c_long) {
    unsafe {
        if pid == 0 {
            syscall(SYS_EXIT_GROUP, 0 as c_long);
        }
        if pid > 0 {
            waitpid(pid as c_int, core::ptr::null_mut(), 0);
        }
    }
}

extern "C" fn thread_body(arg: *mut c_void) -> *mut c_void {
    arg
}

#[no_mangle]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    if argc < 2 {
        return 2;
    }
    let mode = unsafe { core::ffi::CStr::from_ptr(*argv.add(1)) }.to_bytes();
    unsafe {
        match mode {
            // W10: musl's fork() is SYS_fork on x86-64.
            b"fork" => {
                let rc = fork() as c_long;
                let e = *__errno_location();
                reap(rc);
                report(b"fork", rc, e);
            }
            b"raw-fork" => {
                let rc = syscall(SYS_FORK);
                let e = *__errno_location();
                reap(rc);
                report(b"raw-fork", rc, e);
            }
            // W12: musl's pthread_create is clone with CLONE_THREAD.
            b"thread" => {
                let mut t = 0usize;
                let r = pthread_create(
                    &mut t,
                    core::ptr::null(),
                    thread_body,
                    core::ptr::null_mut(),
                );
                if r == 0 {
                    pthread_join(t, core::ptr::null_mut());
                }
                report(b"thread", if r == 0 { 0 } else { -1 }, r);
            }
            _ => return 2,
        }
    }
    7
}
