#include "server.h"
/*
 * Function runServer
 * The main server function
 * Creates a loop for the server run
 */
int run_server(int port_num)
{
    initialize_vars();
    int sockFd = -1, max_fd = 0;
    struct  sockaddr_in server;
    SSL_CTX* theSSLctx = NULL ;
    int opt = 1;
    struct timeval timeout;
    gettimeofday(&timeout,NULL);
    timeout.tv_sec += TIMEOUT_INTERVAL;

    /* Print the banner */
    print_banner();
    /* openssl implementation */
    theSSLctx = initialize_open_SSL_cert();
    if (theSSLctx == NULL)
    {
        debug_s("CTX not initalized");
        exit(1);
    }
    /* server implementation */

    /* Lets initalize the server attributes  */
    server = server_struct_init(port_num);
    sockFd = initalize_server(server);
    debug_sockaddr("Server ip = ", server);
    /* Run the server FOREVER */

    /* Allow multiple binds on main socket, this prevents blocking when debugging */
    if(setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return 1;
    }

    srand(time(NULL));

    /* Initialize connectionList */
    GError* error = NULL;

    /* Load password file */
    keyfile = g_key_file_new();
    if(!g_key_file_load_from_file(keyfile, "passwords.ini",
            G_KEY_FILE_NONE, &error))
        g_debug("%s", error->message);

    connectionList = g_tree_new((GCompareFunc) fd_cmp);
    roomsOnServerList = g_tree_new((GCompareFunc) g_ascii_strcasecmp);
    usersOnServerList = g_tree_new((GCompareFunc) g_ascii_strcasecmp);

    printf("Server is started\n");
    while(1)
    {
        fd_set readFdSet;
        int activity = -1;
        int clientSockFd;
        struct timeval tv;
        struct timeval now;
        iterArgs args;

        tv.tv_sec = TIMEOUT_INTERVAL;
        tv.tv_usec = 0;
        /* zero out connection on sockfd if there is any */
        FD_ZERO(&readFdSet);
        FD_SET(sockFd, &readFdSet);
        /* end of sock set zero */

        max_fd = sockFd;

        /* Set up arguments for iterator function */
        args.readFdSet = &readFdSet;
        args.max_fd = & max_fd;

        /* Iterate over each connection and add it to our fd set */
        g_tree_foreach(connectionList, (GTraverseFunc)iter_add_to_fd_set, &args);

        activity = select(max_fd + 1, &readFdSet, 0, 0, &tv);

        if (activity < 0 && errno != EINTR)
        {
            perror("select");
            return 1;
        }

        gettimeofday(&now,NULL);

        /* Check if the main socket is active then we have an */
        /* incoming connection */
        if (FD_ISSET(sockFd, &readFdSet) && activity > 0)
        {
            struct sockaddr_in *client = g_new0(struct sockaddr_in, 1);
            socklen_t clienLength = (socklen_t) sizeof(client);
            clientSockFd = accept(sockFd, (struct sockaddr*) client, &clienLength);
            SSL* sslclient = NULL;
            sslclient = SSL_new(theSSLctx);
            if (sslclient != NULL)
            {
                debug_s("NEW SSL != NULL");
                int sslErr = -1;
                sslErr = SSL_set_fd(sslclient, clientSockFd);
                if (sslErr < 0)
                {
                    debug_s("SSL_set_fd error: ");
                    ERR_print_errors_fp(stderr);
                }

                sslErr = SSL_accept(sslclient);
                debug_d("SSL ACCEPT = ", sslErr);
                if (sslErr > 0)
                {
                    debug_s("Creating new connection");
                    UserI *new_user = g_new0(UserI, 1); //create new User struct
                    initialize_user_struct(new_user);
                    new_user->sslFd = sslclient;
                    new_user->fd = clientSockFd;
                    new_user->client = client;
                    new_user->login_timeout.tv_sec = now.tv_sec + (TIMEOUT_INTERVAL * 2);
                    g_tree_insert(connectionList, &new_user->fd, new_user);
                    if (SSL_write(sslclient, "Welcome to MapleChat v1.0!", 26) == -1)
                    {
                        debug_s("SSL_WRITE error:");
                        ERR_print_errors_fp(stderr);
                    }
                    debug_s("before log to console");
                    log_to_console(client, "connected");
                    continue;
                }
                else if (sslErr <= 0 || sslErr > 1)
                {
                    debug_s("SSL accept error:");
                    ERR_print_errors_fp(stderr);
                }
            }
            else
            {
                debug_s("SSL new error");
                perror("SSL NEW ERROR = ");
                ERR_print_errors_fp(stderr);
            }
        }

        if(now.tv_sec > timeout.tv_sec)
        {
            debug_s("Checking timeout");
            g_tree_foreach(connectionList, (GTraverseFunc)iter_check_timeout, NULL);

            debug_s("Sending PINGs");
            g_tree_foreach(connectionList, (GTraverseFunc)iter_ping, NULL);

            /* Resetting timeout */
            gettimeofday(&timeout,NULL);
            timeout.tv_sec += TIMEOUT_INTERVAL;
        }

        debug_s("Processing clients");
        g_tree_foreach(connectionList, (GTraverseFunc)iter_connections, &readFdSet);
    }
    /* exit server */
    print_to_output("Server exiting\n", 15);
    g_tree_destroy(connectionList);
    g_tree_destroy(roomsOnServerList);
    g_tree_destroy(usersOnServerList);

    g_key_file_free(keyfile);

    SSL_CTX_free(theSSLctx);
    ERR_remove_state(0);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

}

/*
 * Function serverStructInit()
 * returns a struct for the server initalization
 */
struct sockaddr_in server_struct_init(int port_num)
{
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port_num);
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    return server;
}

/*
 * Function initalize_server()
 * Creates server structure
 * Creates socket
 * Binds to socket
 * Listens to sockets
 * returns sockfd
 */
int initalize_server(struct sockaddr_in server)
{
    debug_s("Initializing the server!");
    int sockFd;

    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd == -1)
    {
        perror("Socket error: ");
        exit(EXIT_FAILURE);
    }


    /* Bind port */
    if (bind(sockFd, (struct sockaddr*)&server, sizeof(server)) ==  -1)
    {
        perror("Bind error: ");
        exit(EXIT_FAILURE);
    }

    /* Listen to port, allow 1 connection */
    if (listen(sockFd, 5) == -1)
    {
        perror("Listen error: ");
        exit(EXIT_FAILURE);
    }

    return sockFd;
}

/*
 * Function initalizeOpenSSLcert
 * For SSL library initalization and configuration
 *
 */
SSL_CTX* initialize_open_SSL_cert()
{
    debug_s("Initializing the openssl certification!");
    SSL_CTX* theSSLctx = NULL;
    SSL_library_init();         //initialize library
    OpenSSL_add_all_algorithms(); //add digest and ciphers
    SSL_load_error_strings();   //load errno strings

    theSSLctx = SSL_CTX_new(TLSv1_server_method());
    if (theSSLctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Lets load the certificate pointed by macros */
    if (SSL_CTX_use_certificate_file(theSSLctx, OPENSSL_SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr); //openssl/err.h
        exit(1); //exit with errors
    }
    /* Lets load the key pointed by the macros */
    if (SSL_CTX_use_PrivateKey_file(theSSLctx, OPENSSL_SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr); //openssl/err.h
        exit(1); //exit with errors
    }

    /* lets check if private key and certificate check out */
    if (!SSL_CTX_check_private_key(theSSLctx))
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_verify(theSSLctx, SSL_VERIFY_NONE, NULL);
    return theSSLctx;
}

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses */
    /* belong to different families, we abort. */

    g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
            (_addr1->sin_family != _addr2->sin_family));

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}

/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
    return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

/*
 * Function logger
 * Used for logging all connections and authentications to console
 *
 */
void logger(struct sockaddr_in *client, int type)
{
    debug_s("Logging to file");
    char port_num[2];
    char buffer[512];
    char theTime[21];
    int len = 20;
    char clBugg[len];
    sprintf(port_num, "%d", ntohs(client->sin_port));
    get_header_time(theTime, 2);
    FILE *logfp = NULL;
    logfp = fopen(LOGFILE, "a+");
    if (logfp == NULL)
    {
        perror("Open logfile error: ");
        return;
    }
    debug_s("Creating log buffer");
    strcat(buffer, theTime);
    strcat(buffer, " : ");
    strcat(buffer, inet_ntop(AF_INET, &(client->sin_addr), clBugg, len));
    strcat(buffer, ":");
    strcat(buffer, port_num);

    if (type == 0)
    {
        strcat(buffer, " connected");
    }
    else if (type == 1)
    {
        strcat(buffer, " disconnected");
    }

    strcat(buffer, "\r\n");
    fprintf(logfp, "%s", buffer);
    printf("%s", buffer);
    fclose(logfp);
    logfp = NULL;
    return;
}

/*
 * Function initialize user struct
 * used for user struct initialitation88
 */
void initialize_user_struct(struct userInformation *new_user)
{
    new_user->sslFd = NULL;
    new_user->fd = -1;
    new_user->username = NULL;
    new_user->nickname = NULL;
    new_user->count_logins = 0;
    new_user->the_game = NULL;
}

/*
 * Function initliaze vars
 * Used to initialize all vars at startup
 */
void initialize_vars()
{
    connectionList = NULL;
    roomsOnServerList = NULL;
    usersOnServerList = NULL;
    keyfile = NULL;

}

