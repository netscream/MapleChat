#include "server.h"

gchar* user_get_hash(gchar* username)
{
    gchar *passwd64 = g_key_file_get_string(keyfile, "passwords",
            username, NULL);
    gsize length;

    if( passwd64 == NULL )
        return NULL;

    gchar *passwd = g_base64_decode(passwd64, &length);
    return passwd;
}

void user_set_hash(gchar* username, gchar* hash)
{
    gchar *hash64 = g_base64_encode(hash, strlen(hash));
    g_key_file_set_string(keyfile, "passwords", username, hash64);
    g_free(hash64);
    /* gsize length; */
    /* gchar *keyfile_string = g_key_file_to_data(keyfile, &length); */
    /* write(fd, keyfile_string, length); */
    /* g_free(keyfile_string); */
}

int user_authenticate(gchar* username, gchar* passwd)
{
    gchar* hash = user_get_hash(username);
    if(hash == NULL)
    {
        /* New user, hash his password and store it */
        user_set_hash(username, passwd);
    }
    else
    {
        /* Check if the given password matches the hash */
        if(g_strcmp0(hash, passwd) == 0)
        {
            /* Authenticated */
        }
        else
        {
            /* Failed, can only happen 3 times until disconnect */
        }
    }

}

void process_message(char* message)
{
    gchar** msg = g_strsplit(message, ":", 0);
    gchar* data = msg[1];

    gchar** command = g_strsplit(msg[0], " ", 0);

    if(g_strcmp0("USER", command[0]) == 0)
        user_authenticate(command[1], data);
    if(g_strcmp0("LIST", command[0]) == 0)
        printf("User requested list\n");
    if(g_strcmp0("WHO", command[0]) == 0)
        printf("User requested list of users\n");
}

gboolean iter_connections(gpointer key, gpointer value, gpointer data)
{
    UserI* user = (UserI* ) value;

    if (FD_ISSET(user->fd, (fd_set *)data))
    {
        printf("Socket %d is active\n", user->fd);
        char message[512];
        memset(message, 0, sizeof(message));
        SSL_read(user->sslFd, message, sizeof(message));
        printf("Message: %s\n", message);
        process_message(message);
    }
    else
    {
        printf("Socket %d is inactive\n", user->fd);
    }

    /* TODO: We may want to make this stop once we find an active connection */
    /* to make this more scalable (what if we have a million users?) */
    return 0;
}

gboolean iter_add_to_fd_set(gpointer key, gpointer value, gpointer data)
{
    UserI* user = (UserI* ) value;
    iterArgs* args = (iterArgs *) data;

    FD_SET(user->fd, args->readFdSet);

    if(user->fd > *(args->max_fd))
        *(args->max_fd) = user->fd;

    return 0;
}

/*
 * Function runServer
 * The main server function
 * Creates a loop for the server run
 */
int runServer(int PortNum)
{
    int sockFd = -1, max_fd = 0;
    struct  sockaddr_in server;
    SSL_CTX* theSSLctx;
    int opt = 1;

    /* Print the banner */
    printBanner();
    /* openssl implementation */
    theSSLctx = initializeOpenSSLCert();
    if (theSSLctx == NULL)
    {
        debugS("CTX not initalized");
        exit(1);
    }
    /* server implementation */

    /* Lets initalize the server attributes  */
    server = serverStructInit(PortNum);
    sockFd = initalizeServer(PortNum, server);
    debugSockAddr("Server ip = ", server);
    /* Run the server FOREVER */

    /* Allow multiple binds on main socket, this prevents blocking when debugging */
    if(setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
    {
        error("setsockopt");
        return 1;
    }

    /* Initialize connectionList */
    connectionList = g_tree_new((GCompareFunc)fd_cmp);

    /* Load password file */
    GKeyFile *keyfile = g_keyfile_new();
    g_key_file_load_from_file(keyfile, "passwords.ini",
            G_KEY_FILE_NONE, NULL);

    while(1)
    {
        fd_set readFdSet;
        int activity = -1;
        int clientSockFd;
        SSL *sslclient;
        struct timeval tv;
        iterArgs args;

        tv.tv_sec = 30;
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

        /* Check if the main socket is active then we have an */
        /* incoming connection */
        if (FD_ISSET(sockFd, &readFdSet) && activity > 0)
        {
            struct sockaddr_in *client = g_new0(struct sockaddr_in, 1);
            socklen_t clienLength = (socklen_t) sizeof(client);
            clientSockFd = accept(sockFd, (struct sockaddr*) &client, &clienLength);

            sslclient = SSL_new(theSSLctx);
            if (sslclient != NULL)
            {
                debugS("NEW SSL != NULL");
                int sslErr = -1;
                sslErr = SSL_set_fd(sslclient, clientSockFd);
                if (sslErr < 0)
                {
                    debugS("SSL_set_fd error: ");
                    ERR_print_errors_fp(stderr);
                }

                sslErr = SSL_accept(sslclient);
                debugD("SSL ACCEPT = ", sslErr);
                if (sslErr > 0)
                {
                    debugS("STUFF");
                    //logger((struct sockaddr_in*) client, 0); //report connection to console
                    UserI *newUser = g_new0(UserI, 1); //create new User struct
                    initializeUserStruct(newUser);
                    newUser->sslFd = sslclient;
                    newUser->fd = clientSockFd;
                    newUser->countLogins = 3;
                    g_tree_insert(connectionList, &newUser->fd, newUser);
                    if (SSL_write(sslclient, "Server: Welcome!", 16) == -1)
                    {
                        debugS("SSL_WRITE error:");
                        ERR_print_errors_fp(stderr);
                    }

                    continue;
                }
                else if (sslErr <= 0 || sslErr > 1)
                {
                    debugS("SSL accept error:");
                    ERR_print_errors_fp(stderr);
                }
            }
            else
            {
                debugS("SSL new error");
                perror("SSL NEW ERROR = ");
                ERR_print_errors_fp(stderr);
            }
        }

        debugS("Processing clients");
        /* TODO: Iterate through all of the clients and check if */
        /* their socket is active */
        g_tree_foreach(connectionList, (GTraverseFunc)iter_connections, &readFdSet);
    }
    /* exit server */
    printToOutput("Server exiting\n", 15);
    g_tree_destroy(connectionList);
    g_tree_destroy(roomsOnServerList);
    g_tree_destroy(usersOnServerList);

    g_key_file_free(keyfile);

    SSL_CTX_free(theSSLctx);
    ERR_remove_state(0);
    ERR_free_strings();
}
/*
 * Function serverStructInit()
 * returns a struct for the server initalization
 */
struct sockaddr_in serverStructInit(int PortNum)
{
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PortNum);
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    return server;
}


/*
 * Function initalizeServer()
 * Creates server structure
 * Creates socket
 * Binds to socket
 * Listens to sockets
 * returns sockfd
 */
int initalizeServer(const int PortNum, struct sockaddr_in server)
{
    debugS("Initializing the server!");
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
SSL_CTX* initializeOpenSSLCert()
{
    debugS("Initializing the openssl certification!");
    SSL_CTX* theSSLctx;
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
}

/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
    return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

void logger(struct sockaddr_in *client, int type)
{
    debugS("Logging to file");
    char portNum[2];
    char buffer[512];
    char theTime[21];
    int len = 20;
    char clBugg[len];
    sprintf(portNum, "%d", ntohs(client->sin_port));
    getHeaderTime(theTime, 2);
    FILE *logfp = NULL;
    logfp = fopen(LOGFILE, "a+");
    if (logfp == NULL)
    {
        perror("Open logfile error: ");
        return;
    }
    debugS("Creating log buffer");
    strcat(buffer, theTime);
    strcat(buffer, " : ");
    strcat(buffer, inet_ntop(AF_INET, &(client->sin_addr), clBugg, len));
    strcat(buffer, ":");
    strcat(buffer, portNum);
    if (type == 0)
    {
        strcat(buffer, " connected");
    }
    else
        if (type == 1)
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

void initializeUserStruct(struct userInformation *newUser)
{
    newUser->sslFd = NULL;
    newUser->fd = -1;
    newUser->username = NULL;
    newUser->nickname = NULL;
    newUser->roomname = NULL;
    newUser->countLogins = 0;
    newUser->logintTimeout = 0;
}
