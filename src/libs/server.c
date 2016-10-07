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
    SSL_CTX*    theSSLctx = NULL;
    SSL* SSL_fds[FD_SETSIZE];
    fd_set readFdSet, writeFdSet, exceptFdSet;

    /* Print the banner */
    printBanner();
	/* openssl implementation */
    initializeOpenSSLCert(theSSLctx);
    /* server implementation */ 

    /* Lets initalize the server attributes  */
    sockFd = initalizeServer(PortNum, server);

    /* Run the server FOREVER */
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    while(1)
    {
        int retval = -1;
        retval = select(FD_SETSIZE, &readFdSet, &writeFdSet, &exceptFdSet, &tv);
        if (retval > 0)
        {

        }
        else
        if (retval < 0)
        {
            perror("Select error: ");
        }
    }
}

/*
 * Function initalizeServer()
 * Creates server structure
 * Creates socket
 * Binds to socket
 * Listens to sockets
 * returns sockfd
 */
int initalizeServer(int PortNum, struct sockaddr_in server)
{
    debugS("Initializing the server!");
    int sockFd;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PortNum);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

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
void initializeOpenSSLCert(SSL_CTX *theSSLctx)
{
    debugS("Initializing the openssl certification!");
    SSL_library_init();         //initialize library
    SSL_load_error_strings();   //load errno strings

    OpenSSL_add_all_algorithms(); //add digest and ciphers
    theSSLctx = SSL_CTX_new(TLSv1_server_method());
    if (theSSLctx == NULL)
    {
        perror("SSL_CTX_new error: ");
        exit(1);
    }

    /* Lets load the certificate pointed by macros */
    if (SSL_CTX_use_certificate_file(theSSLctx, OPENSSL_SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
    {  
        ERR_print_errors_fp(stderr); //openssl/err.h
        exit(1); //exit with errors
    }
    /* Lets load the key pointed by the macros */
    if (SSL_CTX_use_PrivateKey_file(theSSLctx, OPEN_SSL_SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr); //openssl/err.h
        exit(1); //exit with errors   
    }

    SSL_CTX_set_verify(theSSLctx, SSL_VERIFY_NONE, NULL);
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