#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./clients/SPC_open_client.h"
// #include "./clients/SPC_close_client.h"
// #include "./clients/SPC_execve_client.h"

// #define BUFFER_SIZE 1024
#define ITERATION 1000

int main(void) {
	const char *pathname =
		"/home/marlowe/shadow-attack-detector/benchmark/foobar";
	int fd = SPC_open(pathname);

	char read_buffer[128];
	read(fd, read_buffer, 128);

	printf("the contents of %s: %s\n", pathname, read_buffer);
	// SPC_close(fd);
	// SPC_execve();

	return 0;
}
