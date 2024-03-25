#ifndef UTIL_H
#define UTIL_H

void send_fd(int socket_fd, int file_fd);

int recv_fd(const int socket_fd);

void exit_if_error(const int result, const char *message);

#endif // UTIL_H
