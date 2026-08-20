CXX := g++
CXXFLAGS := -std=c++17 -Wall -O2
LDLIBS := -lcrypto

SRC_DIR := src
BIN_DIR := bin

CORE_SRCS := $(SRC_DIR)/crypt.cpp $(SRC_DIR)/sender.cpp $(SRC_DIR)/receiver.cpp $(SRC_DIR)/serializer.cpp

.PHONY: all demo tests run-tests clean

all: demo tests

demo: $(BIN_DIR)/demo

tests: $(BIN_DIR)/test_suite

$(BIN_DIR)/demo: $(SRC_DIR)/main.cpp $(CORE_SRCS)
	mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/test_suite: $(SRC_DIR)/test_suite.cpp $(CORE_SRCS)
	mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR) -o $@ $^ $(LDLIBS)

run-tests: tests
	cd $(SRC_DIR) && ../$(BIN_DIR)/test_suite

clean:
	rm -rf $(BIN_DIR)
