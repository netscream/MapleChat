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
#define deBug 0

/* 
 * Function to print timestamp to output
 */
void printTime();
void debugS(char* message);
void debugTwoS(char* outputMessage, char* outputValue);
void debugD(char* message, int id);
void debugSockAddr(char* message, struct sockaddr_in clientAddr);
void debugMessage(char* message, size_t mSize);
void debugGMessage(gchar** message, size_t mSize);
void debugGHashTable(GHashTable* theHashTable);
#endif