#include <stdio.h>
#include "libs/client.h"


int main(int argc, char **argv)
{
	if (argc != 3) {
    	fprintf(stderr, "Usage: %s <IP addr> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const int server_port = strtol(argv[2], NULL, 10);
    const char *ipaddr = argv[1];

    runClient(ipaddr, server_port);
}
