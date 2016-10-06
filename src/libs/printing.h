#ifndef PRINTING_H
#define PRINTING_H
#include <stdio.h>
#include <netinet/in.h> //for sockaddr_in
#include <arpa/inet.h> //for inet_ntop
#include "debugging.h"

void printToOutput(char* message, int length);
void printToOutputSendHeader(char* header, int oneIfFromClient, struct sockaddr_in clientAddr);
void printToOutputError(char* message, struct sockaddr_in clientAddr);
void printBanner();
void getHeaderTime(char* buffer, int mode);
#endif