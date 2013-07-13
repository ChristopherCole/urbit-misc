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

arkham: build/bin arkham.o jit.o
	$(CXX) -lgmp ${LLVM_LINK_FLAGS} ${OPT} -o build/bin/arkham build/bin/arkham.o build/bin/jit.o

arkham.o: build/bin ${SRC}/arkham.c
	$(CC) -DNOCK_PRODUCTION=${NOCK_PRODUCTION} -DNOCK_LLVM=${NOCK_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/arkham.c -o build/bin/arkham.o

jit.o: build/bin ${SRC}/jit.cpp
	$(CXX) -DNOCK_PRODUCTION=${NOCK_PRODUCTION} -DNOCK_LLVM=${NOCK_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/jit.cpp -o build/bin/jit.o

build/bin:
	mkdir -p build/bin

clean:
	rm -rf build
