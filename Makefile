all:
	cd src && make
	cd cmd && make

check:
	cd tests && make check

clean:
	cd src && make clean
	cd cmd && make clean
	cd tests && make clean
