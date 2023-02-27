INJECTOR_OBJS = injector.o util.o exc_handler.o mach.o mach_excServer.o ptrace.o remote_call.o
CFLAGS = -Wall -fPIC -I../../include

all: libinjector.dylib libinjector.a

libinjector.dylib: $(INJECTOR_OBJS)
	$(CC) -shared -o libinjector.dylib $(INJECTOR_OBJS)

libinjector.a: $(INJECTOR_OBJS)
	$(AR) rcs libinjector.a $(INJECTOR_OBJS)

injector.o: injector.c injector_internal.h ../../include/injector.h
util.o: util.c injector_internal.h ../../include/injector.h
exc_handler.o: exc_handler.c injector_internal.h ../../include/injector.h
mach.o: mach.c injector_internal.h ../../include/injector.h
mach_excServer.o: mach_excServer.c mach_exc.h injector_internal.h ../../include/injector.h
ptrace.o: ptrace.c injector_internal.h ../../include/injector.h
remote_call.o: remote_call.c mach_exc.h injector_internal.h ../../include/injector.h
clean:
	$(RM) libinjector.dylib libinjector.a $(INJECTOR_OBJS)