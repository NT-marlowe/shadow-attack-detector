#ifndef SPC_OPEN_CLIENT_H
#define SPC_OPEN_CLIENT_H

#define OPEN_SOCKET_PATH "/tmp/open.sock"

// Include any necessary libraries or headers here
#include "common_client.h"

// return file descriptor
int SPC_open(const char *pathname);

#endif // SPC_OPEN_CLIENT_H
