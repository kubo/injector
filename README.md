# Injector

**Library for injecting a shared library into a Linux or Windows process**

## Linux

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
technique to load a DLL into another process. However this is a bit improved. It gets
the Win32 error code when `LoadLibrary` fails.

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

    /* attach to a process whose process id is 1234. */
    if (injector_attach(&injector, 1234) != 0) {
        printf("ATTACH ERROR: %s\n", injector_error());
        return;
    }
    /* inject a shared library into the process. */
    if (injector_inject(injector, "/path/to/shared/library") != 0) {
        printf("INJECT ERROR: %s\n", injector_error());
    }
    /* inject another shared library. */
    if (injector_inject(injector, "/path/to/another/shared/library") != 0) {
        printf("INJECT ERROR: %s\n", injector_error());
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

## Windows

injector process \ target process | x64 | 32-bit
---|---|---
**x64**     | success     | failure(*1)
**32-bit**  | failure(*2) | success

*1: failure with `32-bit target process isn't supported by 64-bit process`.  
*2: failure with `64-bit target process isn't supported by 32-bit process`.  

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
