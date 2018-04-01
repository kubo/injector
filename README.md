# Injector

**Library for injecting a shared library into a Linux process**

I was inspired by [`linux-inject`][] and the basic idea came from it.
However the way to call `__libc_dlopen_mode` in `libc.so.6` is
thoroughly different.

* `linux-inject` writes about 80 bytes of code to the target process
  on x86_64. This does only 8 bytes.
* `linux-inject` writes code at the firstly found executable region
  of memory, which may referred by other threads. This writes 8-byte
  code at the entry point of `libc.so.6`, which will be referred by
  nobody unless the libc itself is executed as a program.

This was tested only on Ubuntu 16.04 x86_64. It may not work on other
distributions.

This was tested only for `i386` and `x86_64` programs. This includes
experimental code for `armel`, `armhf` and `aarch64`. However I have
not tested it. If my knowledge got from google is correct and `bkpt`(arm)
and `brk`(aarch64) instructions raise `SIGTRAP` as I guess, it may work.

A command line utility named `injector` is created under the [`cmd`][]
directory after running `make`. The usage is same with the [`inject`][]
command in `linux-inject`.

# Caveats

[Caveat about `ptrace()`][] is same with `linux-inject`.

`__libc_dlopen_mode` interlally calls `malloc()` and `free()`.
If the target process is allocating or freeing memory and
`malloc()` or `free()` holds a lock, this may stop the process
forever. Same caveat is in `linux-inject` also.

# License

Files under [`include`][] and [`src`][] are licensed under LGPL 2.1 or later.
Files under [`cmd`][] are licensed under GPL 2 or later.

[`linux-inject`]: https://github.com/gaffe23/linux-inject
[Caveat about `ptrace()`]: https://github.com/gaffe23/linux-inject#caveat-about-ptrace
[`inject`]: https://github.com/gaffe23/linux-inject#usage
[`cmd`]: cmd
[`include`]: include
[`src`]: src
