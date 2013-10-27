#
# Copyright 2013 Christopher Cole
#

# On OSX/ports: /opt/local/libexec/llvm-3.3/bin/llvm-config
# On Ubuntu/Mint: /usr/lib/llvm-3.3/bin/llvm-config

SRC = src
INCLUDE = include
ifeq ($(origin FAST), undefined)
  OPT = -O0 -g
  ARKHAM_PRODUCTION = false
else
  OPT = -O4
  ARKHAM_PRODUCTION = true
endif
ifeq ($(origin LLVM), undefined)
  ARKHAM_LLVM = false
  LLVM_CC_FLAGS = 
  LLVM_LINK_FLAGS =
else
  ARKHAM_LLVM = true
  LLVM_CC_FLAGS = `llvm-config --cflags`
  LLVM_LINK_FLAGS = `llvm-config --libs --ldflags core analysis executionengine jit interpreter native`
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  CC_FLAGS = -std=c99
  CXX_FLAGS =
  CXX_LINK_FLAGS = -lstdc++
endif
ifeq ($(UNAME_S),Darwin)
  CC_FLAGS = -I/opt/local/include
  CXX_FLAGS = -I/opt/local/include
  CXX_LINK_FLAGS = -L/opt/local/lib -lc++
endif

# -lprofiler 

arkham: build/bin arkham.o jit.o fnv_32.o fnv_64.o
	$(CXX) ${OPT} -o build/bin/arkham build/bin/arkham.o build/bin/jit.o build/bin/fnv.o -lgmp -ljemalloc ${LLVM_LINK_FLAGS} ${CXX_LINK_FLAGS}

arkham.o: build/bin ${SRC}/arkham.c
	$(CC) -DARKHAM_PRODUCTION=${ARKHAM_PRODUCTION} -DARKHAM_LLVM=${ARKHAM_LLVM} ${CC_FLAGS} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/arkham.c -o build/bin/arkham.o

fnv_32.o: build/bin ${SRC}/fnv_32.c
	$(CC) ${CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/fnv_32.c -o build/bin/fnv_32.o

fnv_64.o: build/bin ${SRC}/fnv_64.c
	$(CC) ${CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/fnv_64.c -o build/bin/fnv_64.o

jit.o: build/bin ${SRC}/jit.cpp
	$(CXX) -DARKHAM_PRODUCTION=${ARKHAM_PRODUCTION} -DARKHAM_LLVM=${ARKHAM_LLVM} ${CXX_FLAGS} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/jit.cpp -o build/bin/jit.o

build/bin:
	mkdir -p build/bin

clean:
	rm -rf build

test:
	time (build/bin/arkham - < tests/dec4000000.nock)
