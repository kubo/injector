INJECTOR_OBJS = elf.o injector.o ptrace.o remote_call.o util.o shellcode.o
CFLAGS = -Wall -fPIC -I../../include

all: libinjector.so libinjector.a

libinjector.so: $(INJECTOR_OBJS)
	$(CC) -shared -o libinjector.so $(INJECTOR_OBJS)

libinjector.a: $(INJECTOR_OBJS)
	$(AR) rcs libinjector.a $(INJECTOR_OBJS)

elf.o: elf.c injector_internal.h ../../include/injector.h
injector.o: injector.c injector_internal.h ../../include/injector.h
ptrace.o: ptrace.c injector_internal.h ../../include/injector.h
remote_call.o: remote_call.c injector_internal.h ../../include/injector.h
util.o: util.c injector_internal.h ../../include/injector.h
shellcode.o: shellcode.S

clean:
	$(RM) libinjector.so libinjector.a $(INJECTOR_OBJS)
