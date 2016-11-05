#ifndef SERVER_H
#define SERVER_H
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

#include "debugging.h"
#include "printing.h"
#define LOGFILE "./chatd.log"
/* Openssl definations */
#define OPENSSL_SERVER_CERT "cert/fd.crt"
#define OPENSSL_SERVER_KEY "cert/fd.key"
/* End of openssl definations */
/* Gtrees for implementation*/
GTree *connectionList;
GTree *roomsOnServerList;
GTree *usersOnServerList;
/* end of grees for implementation*/

/* KeyFile to store passwords */
GKeyFile *keyfile;

/* Structures to be used for users */
struct userInformation {
    SSL *sslFd;
    int fd;
    char *username;
    char *nickname;
    char *roomname;
    int countLogins;
    time_t logintTimeout;
};
typedef struct userInformation UserI;
/* end of structures for the users */

struct iterArguments {
    fd_set* readFdSet;
    int* max_fd;
};
typedef struct iterArguments iterArgs;

int runServer(int PortNum);
struct sockaddr_in serverStructInit(const int PortNum);
int initalizeServer(const int PortNum, struct sockaddr_in server);
SSL_CTX* initializeOpenSSLCert();
int sockaddr_in_cmp(const void *addr1, const void *addr2);
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data);
void logger(struct sockaddr_in *client, int type);
void initializeUserStruct(struct userInformation *newUser);
#endif
