# common settings
CC=clang
CFLAGS=-std=c17 -Wall -Wextra -Werror -pedantic
BIN_DIR=bin
TARGET=main

# malware and clients
MAIN=$(wildcard ./*.c)
CLIENT_SOURCES=$(wildcard ./clients/*.c)
CLIENT_HEADERS=$(wildcard ./clients/*.h)

$(TARGET): $(MAIN) $(CLIENT_SOURCES) $(CLIENT_HEADERS)
	$(CC) $(CFLAGS) $(MAIN) $(CLIENT_SOURCES) -o $(BIN_DIR)/$@
	
# serevrs
SERVER_COMMONS := servers/common_server.h ./util.c ./util.h
SERVER_TARGETS := $(patsubst servers/SPC_%_server.c,%,$(wildcard servers/SPC_*_server.c))

all: $(SERVER_TARGETS)

$(SERVER_TARGETS): $(SERVER_COMMONS)
	$(CC) $(CFLAGS) servers/SPC_$@_server.c ./util.c \
		-o $(BIN_DIR)/$@_server

# utilities
.PHONY: run
.PHONY: clean
run: $(TARGET)
	./$(BIN_DIR)/$(TARGET)
clean:
	rm -f $(BIN_DIR)/*
