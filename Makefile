CC=clang
CFLAGS=-std=c17 -Wall -Wextra -Werror -pedantic
TARGET=syscall_benchmark
SRC_DIR=benchmark

SOURCES=$(wildcard $(SRC_DIR)/*.c)
HEADERS=$(wildcard $(SRC_DIR)/*.h)


$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $(SRC_DIR)/$@ 

.PHONY: run
run: $(TARGET)
	rm $(SRC_DIR)/sample.txt
	echo "sample" > $(SRC_DIR)/sample.txt
	./benchmark/$(TARGET)
