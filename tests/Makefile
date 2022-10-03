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

ifneq ($(wildcard /usr/bin/mips-linux-gnu-gcc),)
  BUILD_TARGETS += mips
endif

ifneq ($(wildcard /usr/bin/mipsel-linux-gnu-gcc),)
  BUILD_TARGETS += mipsel
endif

ifneq ($(wildcard /usr/bin/mips64-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mips64
endif

ifneq ($(wildcard /usr/bin/mips64el-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mips64el
endif

ifneq ($(wildcard /usr/bin/mipsisa32r6-linux-gnu-gcc),)
  BUILD_TARGETS += mipsisa32r6
endif

ifneq ($(wildcard /usr/bin/mipsisa32r6el-linux-gnu-gcc),)
  BUILD_TARGETS += mipsisa32r6el
endif

ifneq ($(wildcard /usr/bin/mipsisa64r6-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mipsisa64r6
endif

ifneq ($(wildcard /usr/bin/mipsisa64r6el-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mipsisa64r6el
endif

ifneq ($(wildcard /usr/bin/riscv64-linux-gnu-gcc),)
  BUILD_TARGETS += riscv64
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

mips:
	@echo "=============== build: mips ==============="; \
	CC='mips-linux-gnu-gcc -mabi=32' SUFFIX=-mips32 $(MAKE) build
	CC='mips-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsn32 $(MAKE) build

mipsel:
	@echo "=============== build: mipsel ==============="; \
	CC='mipsel-linux-gnu-gcc -mabi=32' SUFFIX=-mips32el $(MAKE) build
	CC='mipsel-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsn32el $(MAKE) build

mips64:
	@echo "=============== build: mips64 ==============="; \
	CC=mips64-linux-gnuabi64-gcc SUFFIX=-mips64 $(MAKE) build

mips64el:
	@echo "=============== build: mips64el ==============="; \
	CC=mips64el-linux-gnuabi64-gcc SUFFIX=-mips64el $(MAKE) build

mipsisa32r6:
	@echo "=============== build: mipsisa32r6 ==============="; \
	CC='mipsisa32r6-linux-gnu-gcc -mabi=32' SUFFIX=-mipsisa32r6 $(MAKE) build
	CC='mipsisa32r6-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsisan32r6 $(MAKE) build

mipsisa32r6el:
	@echo "=============== build: mipsisa32r6el ==============="; \
	CC='mipsisa32r6el-linux-gnu-gcc -mabi=32' SUFFIX=-mipsisa32r6el $(MAKE) build
	CC='mipsisa32r6el-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsisan32r6el $(MAKE) build

mipsisa64r6:
	@echo "=============== build: mipsisa64r6 ==============="; \
	CC=mipsisa64r6-linux-gnuabi64-gcc SUFFIX=-mipsisa64r6 $(MAKE) build

mipsisa64r6el:
	@echo "=============== build: mipsisa64r6el ==============="; \
	CC=mipsisa64r6el-linux-gnuabi64-gcc SUFFIX=-mipsisa64r6el $(MAKE) build

riscv64:
	@echo "=============== build: riscv64 ==============="; \
	CC=riscv64-linux-gnu-gcc SUFFIX=-riscv64 $(MAKE) build

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
