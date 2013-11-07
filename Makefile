#
# Copyright 2013 Christopher Cole
#

SRC = src
INCLUDE = include
BUILD = build

OS := $(shell uname -s)
ifeq ($(OS),Linux)
  PACKAGE_ROOT = /usr/local
  CC_FLAGS = -std=c99
  CPP_FLAGS = -std=c++11
  LD_FLAGS = -lstdc++
else ifeq ($(OS),Darwin)
  PACKAGE_ROOT = /opt/local
  CC_FLAGS = 
  CPP_FLAGS = -std=c++11
  LD_FLAGS = -lc++
endif

ifeq ($(origin ARKHAM_PRODUCTION), undefined)
  OPT = -O0 -g
  ARKHAM_PRODUCTION = false
else
  OPT = -O4
  ARKHAM_PRODUCTION = true
endif

ifeq ($(origin ARKHAM_LLVM), undefined)
  ARKHAM_LLVM = false
else
  ARKHAM_LLVM = true
  LLVM_ROOT = $(PACKAGE_ROOT)
  SOURCE_FLAGS += -I$(LLVM_ROOT)/include `llvm-config --cflags`
  LD_FLAGS += -L$(LLVM_ROOT)/lib `llvm-config --libs --ldflags bitreader bitwriter core analysis executionengine jit interpreter native`
endif

SOURCE_FLAGS += -I$(INCLUDE) -I$(PACKAGE_ROOT)/include $(OPT)
CC_FLAGS += $(SOURCE_FLAGS)
CPP_FLAGS += $(SOURCE_FLAGS)
LD_FLAGS += -L$(PACKAGE_ROOT)/lib $(OPT)

C_SOURCES := $(wildcard $(SRC)/*.c)
CPP_SOURCES := $(wildcard $(SRC)/*.cpp)
OBJECTS := $(addprefix $(BUILD)/,$(notdir $(C_SOURCES:.c=.o) $(CPP_SOURCES:.cpp=.o)))
LIBS = -lgmp -ljemalloc

all: $(BUILD)/arkham

# consider writing a properties file instead of using '-D'

$(BUILD)/arkham: $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) -o $(BUILD)/arkham $(OBJECTS) $(LIBS) $(LD_FLAGS)

$(BUILD)/%.o: $(SRC)/%.cpp
	@mkdir -p $(@D)
	$(CXX) -DARKHAM_PRODUCTION=$(ARKHAM_PRODUCTION) -DARKHAM_LLVM=$(ARKHAM_LLVM) $(CPP_FLAGS) -c $< -o $@

$(BUILD)/%.o: $(SRC)/%.c
	@mkdir -p $(@D)
	$(CC) -DARKHAM_PRODUCTION=$(ARKHAM_PRODUCTION) -DARKHAM_LLVM=$(ARKHAM_LLVM) $(CC_FLAGS) -c $< -o $@

$(BUILD)/%.bc: $(SRC)/%.c
	@mkdir -p $(@D)
	$(CC) -DARKHAM_PRODUCTION=$(ARKHAM_PRODUCTION) -DARKHAM_LLVM=$(ARKHAM_LLVM) $(CC_FLAGS) -c $< -emit-llvm -o $@

clean:
	rm -rf $(BUILD)

test:
	time ($(BUILD)/arkham - < tests/dec4200000.nock)
