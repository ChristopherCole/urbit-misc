all: build_dir nock5k

build_dir:
	mkdir -p build/bin

nock5k: src/main/cpp/nock5k.cpp
	c++ -O4 nock5k.cpp -lprofiler -lgmp -o build/bin/nock5k
