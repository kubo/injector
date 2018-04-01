all:
	cd src && make
	cd cmd && make

clean:
	cd src && make clean
	cd cmd && make clean
