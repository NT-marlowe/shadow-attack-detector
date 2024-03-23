#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./clients/SPC_open_client.h"
#include "./clients/SPC_close_client.h"
// #include "./clients/SPC_execve_client.h"

// #define BUFFER_SIZE 1024
#define ITERATION 1000

// Makes 5 system calls: fopen->read->write->fclose->execv
// int performSystemCalls(void) {
// 	const char *filename = "./benchmark/sample.txt";
// 	char buffer[BUFFER_SIZE];

// 	// this funciton uses openat, not open.
// 	if (file == NULL) {
// 		perror("fopen failed");
// 		exit(EXIT_FAILURE);
// 	}
// 	while (fgets(buffer, BUFFER_SIZE, file) != NULL) {
// 		printf("%s", buffer);
// 	}

// 	callExecve();

// }

int main(void) {
	const char *pathname = "/home/marlowe/shadow-attack-detector/benchmark/foobar";
	int fd               = SPC_open(pathname);
	SPC_close(fd);
	// // SPC_execve();

	return 0;
}
