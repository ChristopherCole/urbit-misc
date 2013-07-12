#
# Copyright 2013 Christopher Cole
#

# /opt/local/libexec/llvm-3.3/bin

SRC = src
INCLUDE = include
ifeq ($(origin FAST), undefined)
  OPT = -O0 -g
  NOCK_PRODUCTION = false
else
  OPT = -O4
  NOCK_PRODUCTION = true
endif
ifeq ($(origin LLVM), undefined)
  NOCK_LLVM = false
  LLVM_CC_FLAGS = 
  LLVM_LINK_FLAGS = 
else
  NOCK_LLVM = true
  LLVM_CC_FLAGS = `llvm-config --cflags`
  LLVM_LINK_FLAGS = `llvm-config --libs --cflags --ldflags core analysis executionengine jit interpreter native`
endif

# -lprofiler 

nock5k: nock5k.o jit.o
	$(CXX) -lgmp ${LLVM_LINK_FLAGS} ${OPT} -o build/bin/nock5k build/bin/nock5k.o build/bin/jit.o

nock5k.o: build_dir ${SRC}/nock5k.c
	$(CC) -DNOCK_PRODUCTION=${NOCK_PRODUCTION} -DNOCK_LLVM=${NOCK_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/nock5k.c -o build/bin/nock5k.o

nock5k.i: build_dir ${SRC}/nock5k.c
	$(CC) -DNOCK_PRODUCTION=${NOCK_PRODUCTION} -DNOCK_LLVM=${NOCK_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -E ${SRC}/nock5k.c -o build/bin/nock5k.i

jit.o: build_dir ${SRC}/jit.c
	$(CXX) -DNOCK_PRODUCTION=${NOCK_PRODUCTION} -DNOCK_LLVM=${NOCK_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/jit.c -o build/bin/jit.o

jit.i: build_dir ${SRC}/jit.c
	$(CC) -DNOCK_PRODUCTION=${NOCK_PRODUCTION} -DNOCK_LLVM=${NOCK_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -E ${SRC}/jit.c -o build/bin/jit.i

build_dir:
	mkdir -p build/bin

clean:
	rm -rf build
