# /opt/local/libexec/llvm-3.3/bin

LLVM_CC_FLAGS = `llvm-config --cflags`
LLVM_LINK_FLAGS = `llvm-config --libs --cflags --ldflags core analysis executionengine jit interpreter native`
SRC = src/main/cpp
ifeq ($(origin FAST), undefined)
  OPT = -g
  PRODUCTION = false
else
  OPT = -O4
  PRODUCTION = true
endif

nock5k: build_dir ${SRC}/nock5k.cpp
	c++ -DPRODUCTION=${PRODUCTION} -DNOCK_LLVM=false -I${SRC} ${OPT} ${SRC}/nock5k.cpp ${SRC}/lib.cpp -lprofiler -lgmp -o build/bin/nock5k


nock5k-llvm: build_dir ${SRC}/nock5k.cpp ${SRC}/lib.cpp
	c++ -DPRODUCTION=${PRODUCTION} -DNOCK_LLVM=true ${LLVM_CC_FLAGS} -I${SRC} ${OPT} ${SRC}/nock5k.cpp ${SRC}/lib.cpp -lprofiler -lgmp ${LLVM_LINK_FLAGS} -o build/bin/nock5k

nock5k.s: build_dir ${SRC}/nock5k.cpp
	c++ -DPRODUCTION=${PRODUCTION} -DNOCK_LLVM=false -I${SRC} ${OPT} -S -emit-llvm ${SRC}/nock5k.cpp -o build/nock5k.s

nock5k.i: build_dir ${SRC}/nock5k.cpp
	c++ -DPRODUCTION=${PRODUCTION} -DNOCK_LLVM=false -I${SRC} -E ${SRC}/nock5k.cpp -o build/nock5k.i

lib.s: build_dir ${SRC}/lib.cpp
	c++ -DPRODUCTION=${PRODUCTION} -DNOCK_LLVM=false -I${SRC} ${OPT} -S -emit-llvm ${SRC}/lib.cpp -o build/lib.s

build_dir:
	mkdir -p build/bin

clean:
	rm -rf build
