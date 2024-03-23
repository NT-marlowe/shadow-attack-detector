#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>

#include "util.h"

void send_fd(int socket_fd, int file_fd) {
	struct msghdr message;
	struct iovec iov[1];
	struct cmsghdr *control_message = NULL;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	char data[1];

	memset(&message, 0, sizeof(struct msghdr));
	memset(ctrl_buf, 0, CMSG_SPACE(sizeof(int)));

	// sendmsg uses struct msghdr to send ancillary data
	iov[0].iov_base        = data;
	iov[0].iov_len         = sizeof(data);
	message.msg_iov        = iov;
	message.msg_iovlen     = 1;
	message.msg_control    = ctrl_buf;
	message.msg_controllen = CMSG_SPACE(sizeof(int));

	control_message             = CMSG_FIRSTHDR(&message);
	control_message->cmsg_level = SOL_SOCKET;
	control_message->cmsg_type  = SCM_RIGHTS;
	control_message->cmsg_len   = CMSG_LEN(sizeof(int));

	*((int *)CMSG_DATA(control_message)) = file_fd;

	message.msg_controllen = control_message->cmsg_len;

	if (sendmsg(socket_fd, &message, 0) < 0) {
		perror("Failed to send message");
		exit(EXIT_FAILURE);
	}
}

int recv_fd(int socket_fd) {
	struct msghdr msg = {0};
	struct iovec iov[1];
	char buf[CMSG_SPACE(sizeof(int))];
	char data[1];
	int *fd;
	ssize_t n;

	data[0]            = ' ';
	iov[0].iov_base    = data;
	iov[0].iov_len     = sizeof(data);
	msg.msg_iov        = iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = buf;
	msg.msg_controllen = sizeof(buf);

	n = recvmsg(socket_fd, &msg, 0);
	if (n < 0) {
		perror("recvmsg");
		exit(EXIT_FAILURE);
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	fd                   = (int *)CMSG_DATA(cmsg);
	return *fd;
}
