#ifndef STRUCTURES_H
#define STRUCTURES_H
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
/* Structures to be used for users */
typedef struct userInformation
{
    SSL *sslFd;
    int fd;
    char *username;
    char *nickname;
    int count_logins;
    time_t login_timeout;
    struct room_information* current_room;
    struct sockaddr_in* client;
} UserI;
/* end of structures for the users */

typedef struct room_information
{
    char* room_name;
    GList *user_list;
} RoomI;
/* end of structures for the rooms */


typedef struct iterArguments {
    fd_set* readFdSet;
    int* max_fd;
} iterArgs;

typedef struct communication_message {
	gchar* from_user;
	gchar* to_user;
	gchar* message;
} communicateM;

#endif