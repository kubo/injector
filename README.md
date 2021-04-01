# Injector

[![Build Status](https://travis-ci.com/kubo/injector.svg?branch=master)](https://travis-ci.com/kubo/injector)

**Library for injecting a shared library into a Linux or Windows process**

## Linux

**Note: Don't use this library in production environments. This may stop processes forever. See [Caveats](#caveats).**

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

## Windows

Windows version is also here. It uses well-known [`CreateRemoteThread+LoadLibrary`]
technique to load a DLL into another process with some improvements.

1. It gets Win32 error messages when `LoadLibrary` fails by copying assembly
   code into the target process.
2. It can inject a 32-bit dll into a 32-bit process from x64 processes
   by checking the export entries in 32-bit kernel32.dll.

**Note:** It may work on Windows on ARM though I have not tested it because
I have no ARM machines. Let me know if it really works.

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

## Windows

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

injector process \ target process | x86_64 | i386 | x32(*1)
---|---|---|---
**x86_64** | success(*4) | success(*4) | success(*4)
**i386**   | failure(*2) | success(*4) | failure(*3)
**x32**(*1) | failure(*2) | success(*4) | failure(*3)

injector process \ target process | arm64 | armhf | armel
---|---|---|---
**arm64** | success(*4) | success | success
**armhf** | failure(*2) | success | success
**armel** | failure(*2) | success | success

*1: [x32 ABI](https://en.wikipedia.org/wiki/X32_ABI)  
*2: failure with `64-bit target process isn't supported by 32-bit process`.  
*3: failure with `x32-ABI target process is supported only by x86_64`.  
*4: tested on travis-ci  

## Windows

injector process \ target process | x64 | x86 | arm64
---|---|---|---
**x64**     | success(*2) | success(*2) | -
**x86**     | failure(*1) | success(*2) | -
**arm64**   | -           | -           | not tested(*3)

*1: failure with `x64 target process isn't supported by x86 process`.  
*2: tested on travis-ci  
*3: It may work though I have not tested it. Let me know if it really works.

# Caveats

[Caveat about `ptrace()`][] is same with `linux-inject`.

`__libc_dlopen_mode` internally calls `malloc()` and `free()`.
If the target process is allocating or freeing memory and
`malloc()` or `free()` holds a lock, this may stop the process
forever. Same caveat is in `linux-inject` also.

# License

Files under [`include`][] and [`src`][] are licensed under LGPL 2.1 or later.  
Files under [`cmd`][] are licensed under GPL 2 or later.  
Files under [`util`][] are licensed under 2-clause BSD.

[`linux-inject`]: https://github.com/gaffe23/linux-inject
[Caveat about `ptrace()`]: https://github.com/gaffe23/linux-inject#caveat-about-ptrace
[`inject`]: https://github.com/gaffe23/linux-inject#usage
[`cmd`]: cmd
[`include`]: include
[`src`]: src
[`util`]: util
[`CreateRemoteThread+LoadLibrary`]: https://www.google.com/search?&q=CreateRemoteThread+LoadLIbrary
