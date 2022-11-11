UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
OS = macos
else
OS = linux
endif
all:
	cd src/$(OS) && make
	cd cmd && make

check:
	cd tests && make check

clean:
	cd src/$(OS) && make clean
	cd cmd && make clean
	cd tests && make clean
