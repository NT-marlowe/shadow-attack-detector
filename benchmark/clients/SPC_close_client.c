#include "SPC_close_client.h"
#include "../util.h"

int SPC_close(const int target_fd) {
	int socket_fd;
	struct sockaddr_un server_addr;

	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, CLOSE_SOCKET_PATH);

	if (connect(socket_fd, (struct sockaddr *)&server_addr,
			sizeof(struct sockaddr_un)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	send_fd(socket_fd, target_fd);

	char buffer[BUFFER_SIZE];
	read(socket_fd, buffer, BUFFER_SIZE);
	printf("Server Response: %s\n", buffer);

	close(socket_fd);

	return EXIT_SUCCESS;
}
