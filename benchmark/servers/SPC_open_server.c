#include <fcntl.h>

#include "common_server.h"
#include "../util.h"

#define OPEN_SOCKET_PATH "/tmp/open.sock"

int main() {
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
	strcpy(server_addr.sun_path, OPEN_SOCKET_PATH);

	unlink(OPEN_SOCKET_PATH);
	exit_if_error(bind(server_fd, (struct sockaddr *)&server_addr,
					  sizeof(struct sockaddr_un)),
		"bind");

	exit_if_error(listen(server_fd, 5), "listen");

	printf("Server is waiting for client...\n");

	int client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	char pathname[BUFFER_SIZE];
	read(client_fd, pathname, BUFFER_SIZE);
	printf("Received: %s\n", pathname);
	int file_fd = open(pathname, O_RDONLY);

	send_fd(client_fd, file_fd);

	close(file_fd);
	close(client_fd);
	close(server_fd);

	return EXIT_SUCCESS;
}
