#include "SPC_open_client.h"
#include "../util.h"

int SPC_open(const char *pathname) {
	int socket_fd;
	struct sockaddr_un server_addr;
	char buffer[BUFFER_SIZE];
	strcpy(buffer, pathname);

	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, OPEN_SOCKET_PATH);

	exit_if_error(connect(socket_fd, (struct sockaddr *)&server_addr,
					  sizeof(struct sockaddr_un)),
		"connect");

	write(socket_fd, buffer, strlen(buffer) + 1);

	int received_fd = recv_fd(socket_fd);
	printf("Server Response: %d\n", received_fd);

	char buffer_foo[1024];
	ssize_t bytes_read = read(received_fd, buffer_foo, sizeof(buffer) - 1);
	if (bytes_read < 0) {
		perror("read error");
		exit(EXIT_FAILURE);
	}

	buffer_foo[bytes_read] = '\0';
	printf("Received data: %s\n", buffer_foo);

	close(received_fd);
	close(socket_fd);
	return received_fd;
}
