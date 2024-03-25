#include <fcntl.h>

#include "common_server.h"
#include "../util.h"

#define CLOSE_SOCKET_PATH "/tmp/close.sock"

int main(void) {
	int server_fd;
	// contain unix local socket_fd address information
	struct sockaddr_un server_addr;

	// use unix domain socket withy stream type and protocol 0
	server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, CLOSE_SOCKET_PATH);

	unlink(CLOSE_SOCKET_PATH);
	exit_if_error(bind(server_fd, (struct sockaddr *)&server_addr,
					  sizeof(struct sockaddr_un)),
		"bind");

	exit_if_error(listen(server_fd, 5), "listen");

	printf("Close server is waiting for client...\n");

	int client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	int received_fd = recv_fd(client_fd);
	if (received_fd == -1) {
		perror("recv_fd");
		exit(EXIT_FAILURE);
	}

	int result = close(received_fd);

	char write_buffer[BUFFER_SIZE];
	sprintf(write_buffer, "%d", result);
	write(client_fd, write_buffer, strlen(write_buffer) + 1);

	close(received_fd);
	close(client_fd);
	close(server_fd);

	return EXIT_SUCCESS;
}
