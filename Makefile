ifeq ($(OS),Windows_NT)
  SRC_DIR = src/windows
else
  UNAME_S := $(shell uname -s)
  ifeq ($(UNAME_S),Darwin)
    SRC_DIR = src/macos
  else
    SRC_DIR = src/linux
  endif
endif

all:
	cd $(SRC_DIR) && $(MAKE)
	cd cmd && $(MAKE)

check:
	cd tests && $(MAKE) check

clean:
	cd $(SRC_DIR) && $(MAKE) clean
	cd cmd && $(MAKE) clean
	cd tests && $(MAKE) clean
