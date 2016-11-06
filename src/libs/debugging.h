#ifndef DEBUGGING_H
#define DEBUGGING_H
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h> //for inet_ntop
#include <time.h>
#include <glib.h>
#include <glib/gprintf.h>
#include "server.h"

/* 
 * Change this value to 1 (or something other than 0) to get debug function to work for tftp server 
 *
 */
#define debug 1

/* 
 * Function to print timestamp to output
 */
void print_time();
void debug_s(char* message);
void debug_two_s(char* outputMessage, char* outputValue);
void debug_d(char* message, int id);
void debug_sockaddr(char* message, struct sockaddr_in clientAddr);
void debug_message(char* message, size_t mSize);
void debug_gmessage(gchar** message, size_t mSize);

#endif