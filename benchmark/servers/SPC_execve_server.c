#include <sys/wait.h>

#include "common_server.h"

#define EXECVE_SOCKET_PATH "/tmp/execve.sock"

int callExecve(char *executable_path);

int main() {
	int server_fd;
	// contain unix local socket address information
	struct sockaddr_un server_addr;

	// use unix domain socket withy stream type and protocol 0
	server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, EXECVE_SOCKET_PATH);

	unlink(EXECVE_SOCKET_PATH);
	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 5) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	printf("Server is waiting for client...\n");

	int client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	char read_buffer[BUFFER_SIZE];
	read(client_fd, read_buffer, BUFFER_SIZE);
	printf("Received: %s\n", read_buffer);
	int exit_status = callExecve(read_buffer);

	char write_buffer[BUFFER_SIZE];
	sprintf(write_buffer, "Child exited with status: %d", exit_status);
	write(client_fd, write_buffer, strlen(write_buffer) + 1);

	close(client_fd);
	close(server_fd);

	return EXIT_SUCCESS;
}

int callExecve(char *executable_path) {
	pid_t pid = fork();

	if (pid == -1) {
		perror("fork failed");
		exit(EXIT_FAILURE);

	} else if (pid == 0) {
		// chile process
		char *args[] = {executable_path, "/home/marlowe/shadow-attack-detector/benchmark/foobar", NULL};
		execv(executable_path, args);

		perror("execv failed");
		exit(EXIT_FAILURE);

	} else {
		int status = 0;
		waitpid(pid, &status, 0);

		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}

		return EXIT_FAILURE;
	}
}
