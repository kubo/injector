CFLAGS = -Wall -I../include

all: injector

injector: main.o ../src/linux/libinjector.a
	$(CC) -o injector main.o ../src/linux/libinjector.a

main.o: main.c

../src/linux/libinjlib.a:
	cd ../src/linux && make

clean:
	$(RM) injector main.o
