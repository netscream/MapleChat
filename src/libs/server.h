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

/* Openssl definations */
#define OPENSSL_SERVER_CERT "cert/fd.crt"
#define OPEN_SSL_SERVER_KEY "cert/fd.key"
/* End of openssl definations */
/* Gtrees for implementation*/
GTree *roomsOnServerList;
GTree *usersOnServerList;
GTree *authUserList;
/* end of grees for implementation*/
/* Structures to be used for trees */
/* end of structures for the trees */
int runServer(int PortNum);
int initalizeServer(int PortNum, struct sockaddr_in server);
void initializeOpenSSLCert(SSL_CTX *theSSLctx);
int sockaddr_in_cmp(const void *addr1, const void *addr2);
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data);
#endif