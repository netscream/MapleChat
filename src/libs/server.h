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
struct userInformation
{
    SSL *sslFd;
    int fd;
    char *username;
    char *nickname;
    int count_logins;
    time_t login_timeout;
    struct room_information* current_room;
    struct sockaddr_in* client;
};
typedef struct userInformation UserI;
/* end of structures for the users */

struct room_information
{
    char* room_name;
    GList *user_list;
};

typedef struct room_information RoomI;
/* end of structures for the rooms */


struct iterArguments {
    fd_set* readFdSet;
    int* max_fd;
};

struct communication_message {
	gchar* from_user;
	gchar* to_user;
	gchar* message;
};

typedef struct iterArguments iterArgs;

int run_server(int port_num);
struct sockaddr_in server_struct_init(const int port_num);
int initalize_server(const int port_num, struct sockaddr_in server);
SSL_CTX* initialize_open_SSL_cert();
int sockaddr_in_cmp(const void *addr1, const void *addr2);
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data);
//gint room_name_cmp(gconstpointer A,  gconstpointer B, gpointer G_GNUC_UNUSED data);
void logger(struct sockaddr_in *client, int type);
void initialize_user_struct(struct userInformation *new_user);
gboolean iter_users(gpointer key, gpointer value, gpointer data);
gboolean iter_rooms(gpointer key, gpointer value, gpointer data);
gboolean iter_users_privmsg(gpointer key, gpointer value, gpointer data);
//gboolean gstring_is_equal(const gpointer a, const gpointer b);
void process_message(char* message, struct userInformation* user);
int send_to_user_message(struct userInformation user, char* message);
#endif
