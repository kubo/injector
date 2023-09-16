# Injector

[![tests](https://github.com/kubo/injector/actions/workflows/test.yml/badge.svg)](https://github.com/kubo/injector/actions/workflows/test.yml)
[![Static Badge](https://img.shields.io/badge/docs-API_reference-blue)](http://www.jiubao.org/injector/injector_8h.html)

**Library for injecting a shared library into a Linux, Windows and MacOS process**

## Linux

> **Warning**  
> Don't use this in production environments. It may stop target processes forever. See [Caveats](#caveats).

I was inspired by [`linux-inject`][] and the basic idea came from it.
However the way to call `__libc_dlopen_mode` in `libc.so.6` is
thoroughly different.

* `linux-inject` writes about 80 bytes of code to the target process
  on x86_64. This writes only 4 ~ 16 bytes.
* `linux-inject` writes code at the firstly found executable region
  of memory, which may be referred by other threads. This writes it
  at [the entry point of `libc.so.6`][libc_main], which will be referred by
  nobody unless the libc itself is executed as a program.

[libc_main]: https://sourceware.org/git/?p=glibc.git;a=blob;f=csu/version.c;h=8c0ed79c01223e1f12b54d19f90b5e5b7dd78d27;hb=c804cd1c00adde061ca51711f63068c103e94eef#l67

## Windows

Windows version is also here. It uses well-known [`CreateRemoteThread+LoadLibrary`]
technique to load a DLL into another process with some improvements.

1. It gets Win32 error messages when `LoadLibrary` fails by copying assembly
   code into the target process.
2. It can inject a 32-bit dll into a 32-bit process from x64 processes
   by checking the export entries in 32-bit kernel32.dll.

**Note:** It may work on Windows on ARM though I have not tested it because
I have no ARM machines. Let me know if it really works.

## MacOS
The injector connects to the target process using task_for_pid and creates a mach-thread. If dlopen is called in this thread, the target process will fail with an error, however, it is possible to create another thread using pthread_create_from_mach_thread function for Mac >= 10.12 or pthread_create otherwise. In the created thread, the code for loading the library is executed. The second thread is created when injector_inject is called and terminated when injector_detach is called.
# Compilation

## Linux

```shell
$ git clone https://github.com/kubo/injector.git
$ cd injector
$ make
```

The `make` command creates:

| filename | - |
|---|---|
|`src/linux/libinjector.a`  |a static library|
|`src/linux/libinjector.so` |a shared library|
|`cmd/injector`             |a command line program linked with the static library|

## Windows (MSVC)

Open a Visual Studio command prompt and run the following commands:

```shell
$ git clone https://github.com/kubo/injector.git # Or use any other tool
$ cd injector
$ nmake -f Makefile.win32
```

The `nmake` command creates:

| filename | - |
|---|---|
|`src/windows/injector-static.lib`  |a static library (release build)
|`src/windows/injector.dll`         |a shared library (release build)
|`src/windows/injector.lib`         |an import library for `injector.dll`
|`src/windows/injectord-static.lib` |a static library (debug build)
|`src/windows/injectord.dll`        |a shared library (debug build)
|`src/windows/injectord.lib`        |an import library for `injectord.dll`
|`cmd/injector.exe`                 |a command line program linked the static library (release build)|

## Windows (mingw-w64)

On MSYS2:

```shell
$ git clone https://github.com/kubo/injector.git
$ cd injector
$ CC=gcc make
```

Cross-compilation on Linux:

```shell
$ git clone https://github.com/kubo/injector.git
$ cd injector
$ CC=x86_64-w64-mingw32-gcc OS=Windows_NT make
```

The environment variable `OS=Windows_NT` must be set on Linux.

## MacOS

```shell
$ git clone https://github.com/TheOiseth/injector.git
$ cd injector
$ make
```

The `make` command creates:

| filename | - |
|---|---|
|`src/macos/libinjector.a`  |a static library|
|`src/macos/libinjector.dylib` |a shared library|
|`cmd/injector`             |a command line program linked with the static library|

**Important:** in order for the injector process to connect to another process using task_for_pid, it is necessary to [`disable SIP`][] or sign the injector with a self-signed certificate with debugging permission, for this:
```shell
$ cd cmd/macos-sign
$ chmod +x genkey.sh
$ ./genkey.sh
$ chmod +x sign.sh
$ ./sign.sh
```
If injector still does not work after signing, reboot the system.

# Usage

## C API

```c
#include <injector.h>

...

    injector_t *injector;
    void *handle;

    /* attach to a process whose process id is 1234. */
    if (injector_attach(&injector, 1234) != 0) {
        printf("ATTACH ERROR: %s\n", injector_error());
        return;
    }
    /* inject a shared library into the process. */
    if (injector_inject(injector, "/path/to/shared/library", NULL) != 0) {
        printf("INJECT ERROR: %s\n", injector_error());
    }
    /* inject another shared library. */
    if (injector_inject(injector, "/path/to/another/shared/library", &handle) != 0) {
        printf("INJECT ERROR: %s\n", injector_error());
    }

...

    /* uninject the second shared library. */
    if (injector_uninject(injector, handle) != 0) {
        printf("UNINJECT ERROR: %s\n", injector_error());
    }

    /* cleanup */
    injector_detach(injector);
```

## Command line program

See [`Usage` section and `Sample` section in linux-inject][`inject`] and substitute
`inject` with `injector` in the page.

# Tested Architectures

## Linux

x86_64:

injector process \ target process | x86_64 | i386 | x32(*1)
---|---|---|---
**x86_64** | :smiley: success(*2) | :smiley: success(*3) | :smiley: success(*6)
**i386**   | :skull:  failure(*4) | :smiley: success(*3) | :skull:  failure(*5)
**x32**(*1) | :skull:  failure(*4) | :smiley: success(*6) | :skull:  failure(*5)

*1: [x32 ABI](https://en.wikipedia.org/wiki/X32_ABI)  
*2: tested on github actions with both glibc and musl.  
*3: tested on github actions with glibc.  
*4: failure with `64-bit target process isn't supported by 32-bit process`.  
*5: failure with `x32-ABI target process is supported only by x86_64`.  
*6: tested on a local machine. `CONFIG_X86_X32` isn't enabled in github actions.  

ARM:

injector process \ target process | arm64 | armhf | armel
---|---|---|---
**arm64** | :smiley: success     | :smiley: success | :smiley: success
**armhf** | :skull:  failure(*1) | :smiley: success | :smiley: success
**armel** | :skull:  failure(*1) | :smiley: success | :smiley: success

*1: failure with `64-bit target process isn't supported by 32-bit process`.  

MIPS:

injector process \ target process | mips64el | mipsel (n32) | mipsel (o32)
---|---|---|---
**mips64el** | :smiley: success (*1)    | :smiley: success (*1) | :smiley: success (*1)
**mipsel (n32)** | :skull:  failure(*2) | :smiley: success (*1) | :smiley: success (*1)
**mipsel (o32)** | :skull:  failure(*2) | :smiley: success (*1) | :smiley: success (*1)

*1: tested on [debian 11 mips64el](https://www.debian.org/releases/bullseye/mips64el/ch02s01.en.html#idm271) on [QEMU](https://www.qemu.org/).  
*2: failure with `64-bit target process isn't supported by 32-bit process`.  

PowerPC:

* **ppc64le** (tested on [alpine 3.16.2 ppc64le](https://dl-cdn.alpinelinux.org/alpine/v3.16/releases/ppc64le/) on [QEMU](https://www.qemu.org/))
* **powerpc (big endian)** (tested on [ubuntu 16.04 powerpc](https://old-releases.ubuntu.com/releases/xenial/) on [QEMU](https://www.qemu.org/)

RISC-V:

* **riscv64** (tested on [Ubuntu 22.04.1 riscv64 on QEMU](https://wiki.ubuntu.com/RISC-V#Booting_with_QEMU))

## Windows

Windows x64:

injector process \ target process | x64 | x86
---|---|---
**x64**     | :smiley: success(*2) | :smiley: success(*2)
**x86**     | :skull:  failure(*1) | :smiley: success(*2)

*1: failure with `x64 target process isn't supported by x86 process`.  
*2: tested on github actions  

Windows 11 on Arm:

injector process \ target process | arm64 | arm64ec | x64 | x86 | arm32
---|---|---|---|---|---
**arm64**   | :smiley: success | :skull:  failure | :skull:  failure | :skull:  failure | :smiley: success
**arm64ec** | :skull:  failure | :smiley: success | :smiley: success | :skull:  failure | :skull:  failure
**x64**     | :skull:  failure | :smiley: success | :smiley: success | :skull:  failure | :skull:  failure
**x86**     | :skull:  failure | :skull:  failure | :skull:  failure | :smiley: success | :skull:  failure
**arm32**   | :skull:  failure | :skull:  failure | :skull:  failure | :skull:  failure | :smiley: success

[Wine](https://www.winehq.org/) (on Linux x86_64):

injector process \ target process | x64 | x86
---|---|---
**x64**     | :smiley: success | :skull:  failure
**x86**     | :skull:  failure | :smiley: success

## MacOS

injector process \ target process | x64 | arm64
---|---|---
**x64**     | :smiley: success(*1) | :skull:  failure(*2)
**arm64**   | :skull:  failure(*3) | :smiley: success

*1: failure with `x86_64 target process isn't supported by x86_64 process on ARM64 machine`. Tested on github actions.  
*2: failure with `arm64 target process isn't supported by x86_64 process.`  
*3: failure with `x86_64 target process isn't supported by arm64 process.`

# Caveats

**The following restrictions are only on Linux.**

Injector doesn't work where `ptrace()` is disallowed.

* Non-children processes (See [Caveat about `ptrace()`][])
* Docker containers on docker version < 19.03 or linux kernel version < 4.8. You need to pass [`--cap-add=SYS_PTRACE`](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)
to `docker run` to allow it in the environments.
* Linux inside of UserLAnd (Android App) (See [here](https://github.com/kubo/injector/issues/17#issuecomment-1113990177))

Injector calls functions inside of a target process interrupted by `ptrace()`.
If the target process is interrupted while holding a non-reentrant lock and
injector calls a function requiring the same lock, the process stops forever.
If the lock type is reentrant, the status guarded by the lock may become inconsistent.
As far as I checked, `dlopen()` internally calls `malloc()` requiring non-reentrant
locks. `dlopen()` also uses a reentrant lock to guard information about loaded files.

On Linux x86_64 `injector_inject_in_cloned_thread` in place of `injector_inject`
may be a solution of the locking issue. It calls `dlopen()` in a thread created by
[`clone()`]. Note that no wonder there are unexpected pitfalls because some resources
allocated in [`pthread_create()`] lack in the `clone()`-ed thread. Use it at
your own risk.

# License

Files under [`include`][] and [`src`][] are licensed under LGPL 2.1 or later.  
Files under [`cmd`][] are licensed under GPL 2 or later.  
Files under [`util`][] are licensed under 2-clause BSD.

[`linux-inject`]: https://github.com/gaffe23/linux-inject
[Caveat about `ptrace()`]: https://github.com/gaffe23/linux-inject#caveat-about-ptrace
[`inject`]: https://github.com/gaffe23/linux-inject#usage
[`clone()`]: https://man7.org/linux/man-pages/man2/clone.2.html
[`cmd`]: cmd
[`include`]: include
[`pthread_create()`]: https://man7.org/linux/man-pages/man3/pthread_create.3.html
[`src`]: src
[`util`]: util
[`CreateRemoteThread+LoadLibrary`]: https://www.google.com/search?&q=CreateRemoteThread+LoadLIbrary
[`disable SIP`]: https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection
