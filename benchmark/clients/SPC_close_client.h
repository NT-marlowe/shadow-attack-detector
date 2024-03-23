#ifndef SPC_CLOSE_CLIENT_H
#define SPC_CLOSE_CLIENT_H

#define CLOSE_SOCKET_PATH "/tmp/close.sock"

#include "./common_client.h"

// Request the server to run 'close' syscall. Return the result of the close
// syscall.
int SPC_close(const int target_fd);

#endif  // SPC_CLOSE_CLIENT_H
