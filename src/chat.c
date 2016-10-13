#include <stdio.h>
#include "libs/client.h"


int main(int argc, char **argv)
{
	if (argc != 2) {
    	fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const int server_port = strtol(argv[1], NULL, 10);
        runClient(server_port);
}
