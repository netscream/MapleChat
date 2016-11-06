#ifndef GETPASSWD_H
#define GETPASSWD_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
void getpasswd(const char *prompt, char *passwd, size_t size);

#endif