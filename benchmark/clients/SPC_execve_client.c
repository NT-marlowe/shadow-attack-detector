#include "SPC_execve_client.h"

#define EXECUTABLE_PATH "/usr/bin/touch"

int SPC_execve(void) {
	int socket_fd;
	struct sockaddr_un server_addr;
	char buffer[BUFFER_SIZE] = EXECUTABLE_PATH;

	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, EXECVE_SOCKET_PATH);

	if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	write(socket_fd, buffer, strlen(buffer) + 1);

	read(socket_fd, buffer, BUFFER_SIZE);
	printf("Server Response: %s\n", buffer);

	close(socket_fd);
	return EXIT_SUCCESS;
}
