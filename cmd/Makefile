CFLAGS = -Wall -I../include
OBJS = main.o
LIBS =

ifeq ($(OS),Windows_NT)
  SRC_DIR = ../src/windows
  LIBS += -ldbghelp
  OBJS += ya_getopt.o
else
  UNAME_S := $(shell uname -s)
  ifeq ($(UNAME_S),Darwin)
    SRC_DIR = ../src/macos
    OBJS += ya_getopt.o
  else
    SRC_DIR = ../src/linux
  endif
endif

all: injector

injector: $(OBJS) $(SRC_DIR)/libinjector.a
	$(CC) -o injector $(OBJS) $(SRC_DIR)/libinjector.a $(LIBS)

main.o: main.c
ya_getopt.o: ../util/ya_getopt.c
	$(CC) $(CFLAGS) -c ../util/ya_getopt.c
$(SRC_DIR)/libinjlib.a:
	cd $(SRC_DIR) && $(MAKE)

clean:
	$(RM) injector $(OBJS)
