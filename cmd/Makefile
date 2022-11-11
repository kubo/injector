UNAME_S := $(shell uname -s)
CFLAGS = -Wall -I../include

all: injector

ifeq ($(UNAME_S),Darwin)
OBJS = main.o ya_getopt.o
OS = macos
else
OBJS = main.o
OS = linux
endif

injector: $(OBJS) ../src/$(OS)/libinjector.a
	$(CC) -o injector $(OBJS) ../src/$(OS)/libinjector.a

main.o: main.c
ya_getopt.o: ../util/ya_getopt.c
	$(CC) $(CFLAGS) -c ../util/ya_getopt.c
../src/$(OS)/libinjlib.a:
	cd ../src/$(OS) && make

clean:
	$(RM) injector $(OBJS)
