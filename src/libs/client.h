#ifndef CLIENT_
#define CLIENT_H
#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>
#include "debugging.h"
#include "printing.h"
#include "getpasswd.h"

#define OPENSSL_SERVER_CERT "cert/fd.crt"
/* This variable holds a file descriptor of a pipe on which we send a
 * number if a signal is received. */
static int exitfd[2];

/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;
struct sockaddr_in serverAddr;
SSL_CTX* theSSLctx;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user_name;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chat_room;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;

int run_client(const char* server_ip, const int port_num);
void connect_to_server(const char* server, const int port_num);
void signal_handler(int signum);
static void initialize_exitfd(void);
void readline_callback(char *line);
void initialize_openSSL_cert();
#endif
