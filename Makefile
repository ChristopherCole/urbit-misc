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
  CXX_LINK_FLAGS = -lstdc++
endif
ifeq ($(UNAME_S),Darwin)
  CXX_LINK_FLAGS = -lc++
endif

# -lprofiler 

arkham: build/bin arkham.o jit.o
	$(CXX) ${OPT} -o build/bin/arkham build/bin/arkham.o build/bin/jit.o -lgmp ${LLVM_LINK_FLAGS} ${CXX_LINK_FLAGS}

arkham.o: build/bin ${SRC}/arkham.c
	$(CC) -DARKHAM_PRODUCTION=${ARKHAM_PRODUCTION} -DARKHAM_LLVM=${ARKHAM_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/arkham.c -o build/bin/arkham.o

jit.o: build/bin ${SRC}/jit.cpp
	$(CXX) -DARKHAM_PRODUCTION=${ARKHAM_PRODUCTION} -DARKHAM_LLVM=${ARKHAM_LLVM} ${LLVM_CC_FLAGS} ${OPT} -I${INCLUDE} -c ${SRC}/jit.cpp -o build/bin/jit.o

build/bin:
	mkdir -p build/bin

clean:
	rm -rf build
