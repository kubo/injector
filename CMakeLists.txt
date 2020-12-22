set(CMAKE_C_STANDARD 98)
project(dllinjector)

if(WIN32)
  set(SOURCES src/windows/injector.c src/windows/injector.def include/injector.h)
  system(STATUS "WIN32 detected.")
elseif(UNIX)
  set(SOURCES src/linux/injector.c src/linux/injector_internal.h src/linux/ptrace.c src/linux/elf.c src/linux/remote_call.c src/linux/util.c include/injector.h)
  system(STATUS "UNIX detected")
endif()

target_include_directories(dllinjector PRIVATE include/)
target_compile_definitions(dllinjector PRIVATE _CRT_SECURE_NO_WARNINGS)

add_library(dllinjector STATIC SOURCES)
