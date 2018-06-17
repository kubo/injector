all:
	cd src/linux && make
	cd cmd && make

check:
	cd tests && make check

clean:
	cd src/linux && make clean
	cd cmd && make clean
	cd tests && make clean
