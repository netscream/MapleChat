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
#include <openssl/sha.h>

#include "structures.h"
#include "processing.h"
#include "debugging.h"
#include "printing.h"
#include "user.h"
#include "authentication.h"
#include "iterators.h"
#include "game.h"
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

/* All function comments are in c file */
int run_server(int port_num);
struct sockaddr_in server_struct_init(const int port_num);
int initalize_server(struct sockaddr_in server);
SSL_CTX* initialize_open_SSL_cert();
int sockaddr_in_cmp(const void *addr1, const void *addr2);
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data);
void logger(struct sockaddr_in *client, int type);
void initialize_user_struct(struct userInformation *new_user);
void process_message(char* message, struct userInformation* user);
void initialize_vars();
#endif
