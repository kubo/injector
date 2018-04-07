# Injector

**Library for injecting a shared library into a Linux process**

I was inspired by [`linux-inject`][] and the basic idea came from it.
However the way to call `__libc_dlopen_mode` in `libc.so.6` is
thoroughly different.

* `linux-inject` writes about 80 bytes of code to the target process
  on x86_64. This writes only four or eight bytes.
* `linux-inject` writes code at the firstly found executable region
  of memory, which may be referred by other threads. This writes it
  at [the entry point of `libc.so.6`][libc_main], which will be referred by
  nobody unless the libc itself is executed as a program.

[libc_main]: https://github.com/lattera/glibc/blob/master/csu/version.c#L68-L77

This was tested only on Ubuntu 16.04 x86_64 and Debian 8 arm64. It may not work on other
distributions.

A command line utility named `injector` is created under the [`cmd`][]
directory after running `make`. The usage is same with the [`inject`][]
command in `linux-inject`.

# Tested Architectures

injector process \ target process | x86_64 | i386 | x32(*1)
---|---|---|---
**x86_64** | success | success | success
**i386**   | failure(*2) | success | failure(*3)
**x32**(*1) | failure(*2) | success | failure(*3)

injector process \ target process | arm64 | armhf | armel
---|---|---|---
**arm64** | success | success | success
**armhf** | failure(*2) | success | success
**armel** | failure(*2) | success | success

*1: [x32 ABI](https://en.wikipedia.org/wiki/X32_ABI)  
*2: failure with `64-bit target process isn't supported by 32-bit process`.  
*3: failure with `x32-ABI target process is supported only by x86_64`.  

# Caveats

[Caveat about `ptrace()`][] is same with `linux-inject`.

`__libc_dlopen_mode` internally calls `malloc()` and `free()`.
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
[remote_call.c]: src/remote_call.c
