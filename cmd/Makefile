CFLAGS = -Wall -I../include

all: injector

injector: main.o ../src/libinjector.a
	$(CC) -o injector main.o -L../src -Wl,-rpath,`pwd`/../src -linjector

main.o: main.c

../src/libinjlib.a:
	cd ../src && make

clean:
	$(RM) injector main.o
