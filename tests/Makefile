UNAME_M := $(shell uname -m)

BUILD_TARGETS =

ifneq ($(wildcard /usr/bin/x86_64-linux-gnu-gcc),)
  BUILD_TARGETS += x86_64
  ifneq ($(wildcard /usr/lib/gcc/x86_64-linux-gnu/*/32/libgcc.a),)
    BUILD_TARGETS += i386
  endif
  ifneq ($(wildcard /usr/lib/gcc/x86_64-linux-gnu/*/x32/libgcc.a),)
    BUILD_TARGETS += x32
  endif
endif

ifneq ($(wildcard /usr/bin/aarch64-linux-gnu-gcc),)
  BUILD_TARGETS += arm64
endif

ifneq ($(wildcard /usr/bin/arm-linux-gnueabihf-gcc),)
  BUILD_TARGETS += armhf
endif

ifneq ($(wildcard /usr/bin/arm-linux-gnueabi-gcc),)
  BUILD_TARGETS += armel
endif

ifeq ($(BUILD_TARGETS),)
  BUILD_TARGETS = default
endif

LINK_PROG = $(CC) $(CFLAGS)
LINK_TARGET = $(CC) $(CFLAGS) -rdynamic
LINK_LIBRARY = $(CC) $(CFLAGS) -shared -fPIC

CHECK_TARGETS = \
  "x86_64 x86_64" \
  "x86_64 i386" \
  "x86_64 x32" \
  "i386 i386" \
  "x32 i386" \
  "arm64 arm64" \
  "arm64 armhf" \
  "arm64 armel" \
  "armhf armhf" \
  "armhf armel" \
  "armel armhf" \
  "armel armel" \

all: $(BUILD_TARGETS)

default:
	SUFFIX= $(MAKE) build

x86_64:
	@echo "=============== build: x86_64 ==============="; \
	CC='cc -m64' SUFFIX=-x86_64 $(MAKE) build

i386:
	@echo "=============== build: i386 ==============="; \
	CC='cc -m32' SUFFIX=-i386 $(MAKE) build

x32:
	@echo "=============== build: x32 ==============="; \
	CC='cc -mx32' SUFFIX=-x32 $(MAKE) build

arm64:
	@echo "=============== build: arm64 ==============="; \
	CC=aarch64-linux-gnu-gcc SUFFIX=-arm64 $(MAKE) build

armhf:
	@echo "=============== build: armhf ==============="; \
	CC=arm-linux-gnueabihf-gcc SUFFIX=-armhf $(MAKE) build

armel:
	@echo "=============== build: armel ==============="; \
	CC=arm-linux-gnueabi-gcc SUFFIX=-armel $(MAKE) build

build: test-prog$(SUFFIX) test-target$(SUFFIX) test-library$(SUFFIX).so

test-prog$(SUFFIX): test-prog.c
	cd ../src/linux && make clean && make
	$(LINK_PROG) -o $@ $^ ../src/linux/libinjector.a

test-target$(SUFFIX): test-target.c
	$(LINK_TARGET) -o $@ $^

test-library$(SUFFIX).so: test-library.c
	$(LINK_LIBRARY) -o $@ $^

check: all
	@if test -x test-prog -a -x test-target; then \
	   echo "=============== injector: default, target: default ==============="; \
	   ./test-prog || exit $$?; \
	 fi;
	@for target_pair in $(CHECK_TARGETS); do \
	   set -- $$target_pair; \
	   prog=$$1; target=$$2; \
	   if test -x test-prog-$$prog -a -x test-target-$$target; then \
	     echo "=============== injector: $$prog, target: $$target ==============="; \
	     ./test-prog-$$prog $$target || exit $$?; \
	   fi; \
	 done

clean:
	$(RM) test-prog test-prog-* test-target test-target-* test-library test-library-*.so 

.PHONY: default x86_64 i386 x32 arm64 armhf armel build check clean
