#include <string.h>
#include <stdio.h>
#include "libs/server.h"

int main(int argc, char **argv)
{
     if (argc != 2) {
          fprintf(stderr, "Usage: %s <port>\n", argv[0]);
          exit(EXIT_FAILURE);
     }

     const int server_port = strtol(argv[1], NULL, 10);

     /* Initialize OpenSSL (implemented in server.c) */

     /* Receive and handle messages. (implemented in server.c) */
     
     runServer(server_port);
     exit(EXIT_SUCCESS);
}
