#include "client.h"

int runClient(const char* serverIP, const int portNum)
{
    debugS("Run client");
    theSSLctx = NULL;
    initialize_exitfd();
    initializeOpenSSLCert();
    if (theSSLctx == NULL)
    {
        printf("CTX = NULL");
        exit(1);
    }
    connectToServer(serverIP, portNum);

    debugS("SSL connect");
    /* Now we can create BIOs and use them instead of the socket.
     * The BIO is responsible for maintaining the state of the
     * encrypted connection and the actual encryption. Reads and
     * writes to sock_fd will insert unencrypted data into the
     * stream, which even may crash the server.
     */

    /* Set up secure connection to the chatd server. */

    /* Read characters from the keyboard while waiting for input.
    */
    prompt = strdup("> ");
    rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
    for (;;) {
        //debugS("For loop in run server");
        fd_set rfds;
        struct timeval timeout;

        /* You must change this. Keep exitfd[0] in the read set to
           receive the message from the signal handler. Otherwise,
           the chat client can break in terrible ways. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(exitfd[0], &rfds);
        FD_SET(server_fd, &rfds);
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        //debugD("serverfd = ", server_fd);
        //debugD("exitfd = ", exitfd[0]);
        int r = select(exitfd[0] + 3, &rfds, NULL, NULL, &timeout);
        if (r < 0) {
            if (errno == EINTR) {
                /* This should either retry the call or
                   exit the loop, depending on whether we
                   received a SIGTERM. */
                continue;
            }
            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        if (r == 0) {
            write(STDOUT_FILENO, "No message?\n", 12);
            fsync(STDOUT_FILENO);
            /* Whenever you print out a message, call this
               to reprint the current input line. */
            rl_redisplay();
            continue;
        }
        if (FD_ISSET(exitfd[0], &rfds)) {
            /* We received a signal. */
            int signum;

            char message[512];
            if (SSL_read(server_ssl, message, sizeof(message)) == -1)
            {
                perror("SSL read error: ");
            }
            printf("%s\n", message);

            if (signum == SIGINT) {
                /* Don't do anything. */
            } else if (signum == SIGTERM || signum == SIGQUIT) {
                /* Clean-up and exit. */
                break;
            }

        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            rl_callback_read_char();
        }

        /* Handle messages from the server here! */
        if (FD_ISSET(server_fd, &rfds)) {
            debugS("getting messages from server");
            char message[512];
            memset(&message, 0, sizeof(message));
            SSL_read(server_ssl, message, sizeof(message));
            printf("%s", message);
        }
    }
    int sslErr = -1;
    sslErr = SSL_shutdown(server_ssl);
    if (sslErr == -1)
    {
        ERR_print_errors_fp(stderr);
    }
    sslErr = close(server_fd);
    if (sslErr == -1)
    {
        perror("Closing filedescriptor error: ");
        exit(1);
    }
    SSL_free(server_ssl);
    SSL_CTX_free(theSSLctx);
    return 0;
    /* replace by code to shutdown the connection and exit
       the program. */
}
/*
 * Function that serves only to connect to the server we intent to use.
 *
 */
void connectToServer(const char* server, const int portNum)
{
    debugS("Inside connectToServer\n");
    int sslErr = -1;
    memset(&serverAddr, '\0', sizeof(serverAddr));

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("Socket error: ");
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);
    inet_pton(AF_INET, server, &serverAddr.sin_addr);

    connect(server_fd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    /* Use the socket for the SSL connection. */
    if (SSL_set_fd(server_ssl, server_fd) <= 0)
    {
        debugS("SSL set fd error:");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    sslErr = SSL_connect(server_ssl);
    if (sslErr <= 0 || sslErr == 2)
    {
        debugS("SSL connect error:");
        printSSLError(SSL_get_error(server_ssl, sslErr));
    }

}

/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. The
   signal number is sent through a self pipe to notify the main loop
   of the received signal. This avoids a race condition in select. */
void signal_handler(int signum)
{
    int _errno = errno;
    if (write(exitfd[1], &signum, sizeof(signum)) == -1 && errno != EAGAIN) {
        abort();
    }
    fsync(exitfd[1]);
    errno = _errno;
}

static void initialize_exitfd(void)
{
    /* Establish the self pipe for signal handling. */
    if (pipe(exitfd) == -1) {
        perror("pipe()");
        exit(EXIT_FAILURE);
    }

    /* Make read and write ends of pipe nonblocking */
    int flags;
    flags = fcntl(exitfd[0], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_GETFL");
        exit(EXIT_FAILURE);
    }
    flags |= O_NONBLOCK;                /* Make read end nonblocking */
    if (fcntl(exitfd[0], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

    flags = fcntl(exitfd[1], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }
    flags |= O_NONBLOCK;                /* Make write end nonblocking */
    if (fcntl(exitfd[1], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

    /* Set the signal handler. */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;           /* Restart interrupted reads()s */
    sa.sa_handler = signal_handler;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
    char buffer[256];
    if (NULL == line) {
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) ||
            (strncmp("/quit", line, 5) == 0)) {
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    }
    if (strncmp("/game", line, 5) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /game username\n",
                    29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        /* Start game */
        return;
    }
    if (strncmp("/join", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *chatroom = strdup(&(line[i]));

        /* Process and send this information to the server. */

        /* Maybe update the prompt. */
        free(prompt);
        prompt = NULL; /* What should the new prompt look like? */
        rl_set_prompt(prompt);
        return;
    }
    if (strncmp("/list", line, 5) == 0) {
        debugS("Requesting list");

        if (SSL_write(server_ssl, "LIST", strlen("LIST")) == -1)
        {
            debugS("SSL_WRITE error:");
            ERR_print_errors_fp(stderr);
        }
        /* Query all available chat rooms */
        return;
    }
    if (strncmp("/roll", line, 5) == 0) {
        /* roll dice and declare winner. */
        return;
    }
    if (strncmp("/say", line, 4) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n",
                    29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        /* Skip whitespace */
        int j = i+1;
        while (line[j] != '\0' && isgraph(line[j])) { j++; }
        if (line[j] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n",
                    29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *receiver = strndup(&(line[i]), j - i - 1);
        char *message = strndup(&(line[j]), j - i - 1);

        /* Send private message to receiver. */

        return;
    }
    if (strncmp("/user", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /user username\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *new_user = strdup(&(line[i]));

        char passwd[48];
        getpasswd("Password: ", passwd, 48);

        /* Process and send this information to the server. */

        gchar* request = g_strconcat("USER ", new_user, ":", passwd, NULL);
        if (SSL_write(server_ssl, request, strlen(request)) == -1)
        {
            debugS("SSL_WRITE error:");
            ERR_print_errors_fp(stderr);
        }
        g_free(request);


        /* Maybe update the prompt. */
        free(prompt);
        prompt = NULL; /* What should the new prompt look like? */
        rl_set_prompt(prompt);
        return;
    }
    if (strncmp("/who", line, 4) == 0) {
        /* Query all available users */
        if (SSL_write(server_ssl, "WHO", strlen("WHO")) == -1)
        {
            debugS("SSL_WRITE error:");
            ERR_print_errors_fp(stderr);
        }
        return;
    }
    /* Sent the buffer to the server. */
    snprintf(buffer, 255, "Message: %s\n", line);
    write(STDOUT_FILENO, buffer, strlen(buffer));
    fsync(STDOUT_FILENO);
}

void initializeOpenSSLCert()
{
    debugS("Initialize openssl");
    /* Initialize OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    theSSLctx = SSL_CTX_new(TLSv1_client_method());
    if (theSSLctx == NULL)
    {
        debugS("SSL ctx new error: ");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Lets load the certificate pointed by macros */
    if (SSL_CTX_use_certificate_file(theSSLctx, OPENSSL_SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
    {
        debugS("CTX certificate error: ");
        ERR_print_errors_fp(stderr); //openssl/err.h
        exit(1); //exit with errors
    }

    SSL_CTX_set_verify(theSSLctx, SSL_VERIFY_NONE, NULL);
    server_ssl = SSL_new(theSSLctx);
    if (server_ssl == NULL)
    {
        debugS("CTX set verify error: ");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    /* Create and set up a listening socket. The sockets you
     * create here can be used in select calls, so do not forget
     * them.
     */
}

void printSSLError(int err)
{
    switch (err)
    {
        case SSL_ERROR_NONE: // Success
            break;
        case SSL_ERROR_SSL:
            printf("SSL_ERROR_SSL:\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        case SSL_ERROR_WANT_READ:
            printf ("SSL_ERROR_WANT_READ:\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        case SSL_ERROR_WANT_WRITE:
            printf("SSL_ERROR_WANT_WRITE:\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        case SSL_ERROR_WANT_CONNECT:
            printf("SSL_ERROR_WANT_CONNECT:\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        case SSL_ERROR_SYSCALL:
            printf("SSL_ERROR_SYSCALL:\n");
            exit(1);
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL_ERROR_SYSCALL:\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        default:
            printf("Unknown error:");
            ERR_print_errors_fp(stderr);
            exit(1);
    }
}
