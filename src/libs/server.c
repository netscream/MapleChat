#include "server.h"

/*
 * Function runServer
 * The main server function
 * Creates a loop for the server run
 */
int runServer(int PortNum)
{
    int sockFd = -1;
    struct  sockaddr_in server;
    SSL_CTX* theSSLctx = NULL;

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
    
    while(1)
    {
        fd_set readFdSet;
        int retval = -1;
        int clientSockFd;
        SSL *ssl;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        /* zero out connection on sockfd if there is any */
        FD_ZERO(&readFdSet);
        FD_SET(sockFd, &readFdSet);
        /* end of sock set zero */

        retval = select(sockFd+1, &readFdSet, 0, 0, &tv);
        if (retval > 0)
        {
            if (FD_ISSET(sockFd, &readFdSet))
            {
                struct sockaddr_in *client = g_new0(struct sockaddr_in, 1);
                socklen_t clienLength = (socklen_t) sizeof(client);
                clientSockFd = accept(sockFd, (struct sockaddr*) &client, &clienLength);

                ssl = SSL_new(theSSLctx);
                if (ssl != NULL)
                {
                    debugS("NEW SSL != NULL");
                    SSL_set_fd(ssl, clientSockFd);

                    int sslErr = -1;
                    sslErr = SSL_accept(ssl);
                    if (sslErr > 0)
                    {
                        logger((struct sockaddr_in*) client, 0); //report connection to console
                        UserI *newUser = g_new0(UserI, 1); //create new User struct
                        initializeUserStruct(newUser);
                        newUser->sslFd = ssl;
                        newUser->fd = clientSockFd;
                        g_tree_insert(connectionList, client, newUser);
                        if (SSL_write(ssl, "Server: Welcome!", 16) == -1)
                        {
                            debugS("SSL_WRITE error:");
                            ERR_print_errors_fp(stderr);
                        }
                    }
                    else if (sslErr == -1)
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

        }
        else
        if (retval == -1)
        {
            perror("Select error: ");
        }
    }
    /* exit server */
    printToOutput("Server exiting\n", 15);
    g_tree_destroy(connectionList);
    g_tree_destroy(roomsOnServerList);
    g_tree_destroy(usersOnServerList);

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
    if (listen(sockFd, 1) == -1)
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
    SSL_load_error_strings();   //load errno strings

    OpenSSL_add_all_algorithms(); //add digest and ciphers
    theSSLctx = SSL_CTX_new(SSLMETHOD);
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

     /* If either of the pointers is NULL or the addresses
        belong to different families, we abort. */
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