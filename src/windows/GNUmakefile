INJECTOR_OBJS = injector.o
CFLAGS = -I../../include

all: injector.dll injector-static.lib

injector.dll: $(INJECTOR_OBJS)
	$(CC) -shared -o $@ $(INJECTOR_OBJS) $(CFLAGS) -Wl,--out-implib,injector.lib -ldbghelp

injector-static.lib: $(INJECTOR_OBJS)
	$(RM) $@
	$(AR) rcs -o $@ $(INJECTOR_OBJS)

clean:
	$(RM) injector.dll injector.lib injector-static.lib $(INJECTOR_OBJS)

