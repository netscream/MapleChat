#ifndef PRINTING_H
#define PRINTING_H
#include <stdio.h>
#include <netinet/in.h> //for sockaddr_in
#include <arpa/inet.h> //for inet_ntop
#include "debugging.h"
/* All function comments are in c file */

void print_to_output(char* message, int length);
void print_to_output_send_header(char* header, int oneIfFromClient, struct sockaddr_in clientAddr);
void print_to_output_error(char* message, struct sockaddr_in client_addr);
void print_banner();
void get_header_time(char* buffer, int mode);
void log_to_console(struct sockaddr_in *client_addr, char *connection_state);
void print_SSL_error(int err);
#endif