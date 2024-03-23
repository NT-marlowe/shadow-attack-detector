#ifndef UTIL_H
#define UTIL_H

void send_fd(int socket_fd, int file_fd);

int recv_fd(const int socket_fd);

#endif // UTIL_H
