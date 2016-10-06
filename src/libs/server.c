#include "server.h"


/*
 * Function runServer
 * The main server function
 * Creates a loop for the server run
 */
int runServer(int PortNum)
{
	int sockfd = -1;
    int retSel = -1;
    struct sockaddr_in server, client;
    char message[512];
    fd_set readSocketFd;
    sockfd = sockInit(); //initalize socket
    server = serverStructInit(PortNum);
    bindListenInit(server, sockfd);

    FD_ZERO(&readSocketFd);
    FD_SET(sockfd, &readSocketFd);
    while(1)
    {   
        memset(&message, 0, sizeof(message));
        memset(&client, 0, sizeof(client));
        retSel = -1;
        int newConnectionFd = -1;
        socklen_t clientLen = (socklen_t) sizeof(client);
        debugS("Before select()");
        if ((retSel = select(sockfd+MAXCLIENTS, &readSocketFd, 0, 0, 0)) == -1)
        {
            perror("Select() error: ");
        }
        else 
        if (retSel > 0)
        {
            debugS("Retsel > 0");
            for (int nextSock = 0; nextSock < sockfd+MAXCLIENTS; nextSock++) //FD_SETSIZE = 1024 man select()
            {
                if (FD_ISSET(nextSock, &readSocketFd))
                {
                    if (nextSock == sockfd)
                    {
                        debugS("Trying to accept new connection");
                        newConnectionFd = accept(sockfd, (struct sockaddr*) &client, &clientLen);
                        debugD("Connection filedescriptor", newConnectionFd);
                        if (newConnectionFd == -1)
                        {
                            perror("Accept error: ");
                        }
                        int sizeofMes = read(newConnectionFd, message, sizeof(message)-1);
                        if (sizeofMes == -1)
                        {
                            perror("Read from socket error: ");
                        }
                        message[sizeof(message)-1] = 0;
                        debugSockAddr(message, client);
                        decodeMessage(newConnectionFd, &client, message);
                        shutdown(newConnectionFd, SHUT_RDWR);
                        close(newConnectionFd);
                    }
                }
            }
        }
        else 
        if (retSel == 0)
        {
            debugS("No filedescriptors available");
        }
        debugS("After retsel");
	}
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
	return -1;
}

/*
 * Function sockInit()
 * Creates socket and sets options for the socket.
 */
int sockInit()
{
    /*  
     *  From man page
     *  SOCK_STREAM
     *  Provides sequenced, reliable, two-way, connection-based byte streams. An out-of-band data transmission mechanism may be supported. 
     */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);  
    if (sockfd == -1) {
        perror("Unable to create socket: ");
        return -1; // no use to continue if no socket, return -1 with error.
    }
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, 0, sizeof(SO_REUSEADDR));  //set reuse of address
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT , 0, sizeof(SO_REUSEPORT ));  //set reuse of port
    return sockfd;
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
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PortNum);
    return server;
}

/*
 * Function bindListenInit
 * void function to bind socket and start listen on port.
 */
void bindListenInit(struct sockaddr_in server, int sockfd)
{
    int retErr = bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
    if (retErr == -1)
    {
        perror("Bind error:");
        exit(1); // no use to continue if unable to bind socket
    }

    retErr = listen(sockfd, MAXCLIENTS);
    if (retErr == -1)
    {
        perror("Listen error:");
        exit(1);
    }
}

/*
 * Function decodeMessage
 * Void function for decoding of recvd message.
 * Calls appropiate functions if HEADER contains "GET, POST or HEAD"
 */
void decodeMessage(int sockfd, struct sockaddr_in *client, char* message)
{
    char bufferHTML[HTMLSIZE];
    char header[HEADERSIZE];

    printToOutputSendHeader(message, 1, *client);
    gchar** splitMessage = g_strsplit(message, " ", 4); // element[0] = request, element[1] = path+uri
    gchar** splitToPath = g_strsplit(splitMessage[1], "/", -1);
    gchar** splitToRequestUrlPathFilter = g_strsplit(splitMessage[1], "?", -1);

    GHashTable* uriElements = g_hash_table_new(NULL, NULL); //lets create hash table
    debugGMessage(splitMessage, g_strv_length(splitMessage));

    createUriHashTable(splitToRequestUrlPathFilter[g_strv_length(splitToRequestUrlPathFilter)-1], uriElements, message); 
    char* response;
    char* request = splitMessage[0];
    char* requestedURL = splitToRequestUrlPathFilter[0];
    //char* requestQuery = splitToPath[g_strv_length(splitToPath)-1];
    char* requestQuery = splitToRequestUrlPathFilter[g_strv_length(splitToRequestUrlPathFilter)-1];
    /* Check if correct HTTP version */
    if (!g_str_has_prefix(splitMessage[2], HTTP_VERSION))
    {
        debugS("HTTP version is wrong");
        response = "505 HTTP Version Not Supported";
        char sendErrMessage[42];
        memset(&sendErrMessage, 0, 42);
        strcat(sendErrMessage, "Other: please use http version = ");
        strcat(sendErrMessage, HTTP_VERSION);
        createHeader(header, 0, 505, sendErrMessage, client, uriElements);
        int wrError = -1;
        wrError = write(sockfd, &header, strlen(header));
        if ( wrError == -1)
        {
            perror("Write error: ");
        }
    }
    else /* If request is GET request */
    if (g_str_has_prefix(splitMessage[0], HTTP_GET))
    {
        debugS("GET");
        response = "200 OK";
        generateHTML(bufferHTML, *client, 0, NULL, requestedURL, requestQuery, uriElements);
        int HTMLLEN = strlen(bufferHTML);
        createHeader(header, HTMLLEN, 200, NULL, client, uriElements);
        int wrError = -1;
        wrError = write(sockfd, &header, strlen(header));
        if ( wrError == -1)
        {
            perror("Write error: ");
        }
        wrError = write(sockfd, &bufferHTML, HTMLLEN);
        if ( wrError == -1)
        {
            perror("Write error: ");
        }
    }
    else /* if request is POST request */
    if (g_str_has_prefix(splitMessage[0], HTTP_POST))
    {
        debugS("POST");
        response = "200 OK";
        gchar** splitPostMessage = g_strsplit((gchar*) message, (gchar*) "\n", -1);
        gchar* postContent = splitPostMessage[g_strv_length(splitPostMessage)-1];
        generateHTML(bufferHTML, *client, 1, postContent, requestedURL, NULL, uriElements);
        int HTMLLEN = strlen(bufferHTML);
        createHeader(header, HTMLLEN, 200, NULL, client, uriElements);
        int wrError = -1;
        wrError = write(sockfd, &header, strlen(header));
        if ( wrError == -1)
        {
            perror("Write error: ");
        }
        wrError = write(sockfd, &bufferHTML, HTMLLEN);
        if ( wrError == -1)
        {
            perror("Write error: ");
        }
        g_strfreev(splitPostMessage);
    }
    else /* if request is HEAD request */
    if (g_str_has_prefix(splitMessage[0], HTTP_HEAD))
    {
        debugS("HEAD");
        response = "200 OK";
        createHeader(header, 0, 200, NULL, client, uriElements);
        int wrError = -1; 
        wrError = write(sockfd, &header, strlen(header));
        if ( wrError == -1)
        {
            perror("Write error: ");
        }
    }
    else /* All other requests are not allowed */
    {
        debugS("OTHER");
        response = "418 I'm a teapot";
        createHeader(header, 0, 418, "Other: METHOD NOT SUPPORTED", client, uriElements);
        int wrError = -1;
        wrError = write(sockfd, &header, strlen(header));
        if ( wrError == -1)
        {
            perror("Write error: ");
        }
    }
    logToFile(*client, request, response, requestedURL);
    deleteAllUriHashTable(uriElements);
    g_strfreev(splitToRequestUrlPathFilter);
    g_strfreev(splitMessage);
    g_strfreev(splitToPath);
}

/*
 * Function logToFile
 * For logfile creation and maintenance
 */
void logToFile(struct sockaddr_in client, char* request, char* response, char* requestedUrl)
{
    debugS("Logging to file");
    int len = 20;
    char clBugg[len];
    char buffer[512];
    memset(&buffer, 0, 512);
    char theTime[21];
    char portID[2];
    sprintf(portID,"%d", ntohs(client.sin_port));
    getHeaderTime(theTime, 2);
    FILE* logfp;
    logfp = fopen(LOGFILE, "a+");
    if (logfp == NULL)
    {
        perror("Open logfile error: ");
        return;
    }
    debugS("Creating buffer");
    strcat(buffer, theTime); //time ISO-8601 compliant
    strcat(buffer, " : ");
    strcat(buffer, inet_ntop(AF_INET, &(client.sin_addr), clBugg, len)); //ip address
    strcat(buffer, ":");
    strcat(buffer, portID); //port
    strcat(buffer, " ");
    strcat(buffer, request);
    strcat(buffer, " ");
    strcat(buffer, requestedUrl);
    strcat(buffer, " : ");
    strcat(buffer, response);
    strcat(buffer, "\n");
    debugS(buffer);
    fprintf(logfp, "%s", buffer);
    debugS("Printing to filedescriptor");
    fclose(logfp);
    debugS("Closing filedescriptor");
    logfp = NULL;
    debugS("Returning from logtofile");
    return;
}

/*
 * Function createHeader
 * Creates the HEADER buffer
 */
void createHeader(char* header, int sizeOfContent, int statusCode, char* optionalMessage, struct sockaddr_in *client, GHashTable* requestHashTable)
{
    memset(header, 0, HEADERSIZE);
    char theTime[40];
    getHeaderTime(theTime, 1);
    char theSizeOfContent[4];
    sprintf(theSizeOfContent, "%d", sizeOfContent);
    if (statusCode == 505)
    {
        strcat(header, "HTTP/1.1 505 HTTP Version Not Supported\r\n");
    }
    else
    if (statusCode == 418)
    {
        strcat(header, "HTTP/1.1 418 I'm a teapot\r\n");
    }
    else
    if (statusCode == 405)
    {
        strcat(header, "HTTP/1.1 405 Method Not Allowed\r\n");
        strcat(header, "Allow: GET, POST, HEADER\r\n");
    }
    else
    if (statusCode == 404)
    {
        strcat(header, "HTTP/1.1 404 Not Found\r\n");
    }
    else
    if (statusCode == 200)
    {
        strcat(header, "HTTP/1.1 200 OK\r\n");
    }
    else
    {

    }
    strcat(header, "Date: ");
    strcat(header, theTime);
    strcat(header, "\r\n");
    strcat(header, "Content-type: text/html\r\n");
    gchar* color = keyToValueFromHashtable(requestHashTable, COLOR_BG_PREFIX);
    if (color != NULL)
    {
        strcat(header, "Set-Cookie: ");
        strcat(header, COLOR_BG_PREFIX);
        strcat(header, "=");
        strcat(header, color);
        strcat(header, "\r\n");
    }
    strcat(header, "Content-length: ");
    strcat(header, theSizeOfContent);
    strcat(header, "\r\n");
    strcat(header, "Connection: keep-live\r\n");
    strcat(header, "Server: Foo/1.0\r\n");
    if (optionalMessage != NULL)
    {
        strcat(header, optionalMessage);
    }
    strcat(header, "\r\n\r\n");
    printToOutputSendHeader(header, 0, *client);
    return;
}

/*
 * Function generateHTML
 * Creates the HTML code buffer, for writing to appropiate filedescriptor
 */
 void generateHTML(char* buffer, struct sockaddr_in client, int method, char* postBuffer, char* requestPage, char* queries, GHashTable* requestHashTable)
{
    memset(buffer, 0, HTMLSIZE);
    debugS("Inside generateHTML");
    int len = 20;
    char clBugg[len];
    char portID[2];
    sprintf(portID,"%d", ntohs(client.sin_port));
    strcat(buffer, "<!DOCTYPE html>\r\n");
    strcat(buffer, "<html>\r\n");
    strcat(buffer, "<title>");
    strcat(buffer, "http://foo.com");
    if (requestPage[0] != '/')
    {
        strcat(buffer, "/");
    }
    else
    {
        strcat(buffer, requestPage);
    }
    strcat(buffer, " ");
    strcat(buffer, inet_ntop(AF_INET, &(client.sin_addr), clBugg, len));
    strcat(buffer, ":");
    strcat(buffer, portID);
    strcat(buffer, " ");
    strcat(buffer, "</title>\r\n");
    strcat(buffer, "<head>\r\n");
    strcat(buffer, "<meta charset=\"UTF-8\">\r\n"); 
    strcat(buffer, "<meta http-equiv=\"Content-Type\" content=\"text/html;charset=ISO-8859-1\">\r\n");
    strcat(buffer, "</head>\r\n");

    debugGHashTable(requestHashTable);
    gchar* getColor = keyToValueFromHashtable(requestHashTable, COLOR_BG_PREFIX);
    if (queries != NULL && strstr(requestPage, "test"))
    {
        strcat(buffer, "<h1>");
        strcat(buffer, "http://foo.com");
        if (requestPage[0] != '/')
        {
            strcat(buffer, "/");
        }
        else
        {
            strcat(buffer, requestPage);
        }
        strcat(buffer, " ");
        strcat(buffer, inet_ntop(AF_INET, &(client.sin_addr), clBugg, len));
        strcat(buffer, ":");
        strcat(buffer, portID);
        strcat(buffer, " ");
        strcat(buffer, "</h1>\r\n");
        strcat(buffer, "<h1>");
        strcat(buffer, queries);
        strcat(buffer, "</h1>\r\n");
    }
    else
    if (getColor != NULL && (strstr(requestPage, "colour") || strstr(requestPage, "color")))
    {
        debugS("It contains colour");
        strcat(buffer, "<body style=\"background-color:");
        strcat(buffer, (gchar*) getColor);
        strcat(buffer, "\">");
    }
    else
    {
        strcat(buffer, "<h1>\r\n");
        if (method == 0)
        {
            strcat(buffer, "<h1>");
            strcat(buffer, "http://foo.com");
            if (requestPage[0] != '/')
            {
                strcat(buffer, "/");
            }
            else
            {
                strcat(buffer, requestPage);
            }
            strcat(buffer, " ");
            strcat(buffer, inet_ntop(AF_INET, &(client.sin_addr), clBugg, len));
            strcat(buffer, ":");
            strcat(buffer, portID);
            strcat(buffer, " ");
            strcat(buffer, "</h1>\r\n");
        }
        else
        if (method == 1 && postBuffer != NULL)
        {
            strcat(buffer, postBuffer);
            strcat(buffer, "\r\n");
        }
        else
        {
            strcat(buffer, "No data posted, please try again!");
        }
        strcat(buffer, "</h1>\r\n");   
    }
    strcat(buffer, "</body>\r\n");
    strcat(buffer, "</html>\r\n");
    strcat(buffer, "\r\n\r\n");
    debugS("Finished creating HTML");
    return;
}

/*
 * Function createUriHashTable
 * Create HashTable from received message
 */
void createUriHashTable(char* urlFromMessage, GHashTable* uriElements, char* message)
{
    debugS("Inside create HashTable");
    debugTwoS("UrlMessage", urlFromMessage);
    if (urlFromMessage != NULL && strstr(urlFromMessage, COLOR_BG_PREFIX) &&!strstr(urlFromMessage, "/"))
    {
        gchar** splitUrl = g_strsplit(urlFromMessage, "&", -1);
        for (int i = 0; splitUrl[i] != NULL; i++)
        {
            gchar** splitElement = g_strsplit(splitUrl[i], "=", -1); 
            gpointer key = g_memdup(splitElement[0], strlen(splitElement[0])+1);
            gpointer value = g_memdup(splitElement[1], strlen(splitElement[1])+1);
            g_hash_table_add(uriElements, key);
            g_hash_table_insert(uriElements, key, value);            
            g_strfreev(splitElement);
        }
        g_strfreev(splitUrl);
    }
    else
    if (g_hash_table_size(uriElements) == 0 || keyToValueFromHashtable(uriElements, COLOR_BG_PREFIX) != NULL)
    {
        if (strstr(message, "Cookie"))
        {
            gchar** splitMessage = g_strsplit(message, "\n", -1);
            for(int i = 0; splitMessage[i] != NULL; i++)
            {
                if (strstr(splitMessage[i], "Cookie"))
                {
                    gchar** splitCookie = g_strsplit(splitMessage[i], " ", -1);
                    if(g_hash_table_size(uriElements) == 0)
                    {
                        gchar** splitElement = g_strsplit(splitCookie[1], "=", -1);
                        gpointer key = g_memdup(splitElement[0], strlen(splitElement[0]+1));
                        gpointer value = g_memdup(splitElement[1], strlen(splitElement[1])+1);
                        g_hash_table_add(uriElements, key);
                        g_hash_table_insert(uriElements, key, value);
                        g_strfreev(splitElement);
                    }
                    g_strfreev(splitCookie);
                }
            }
            g_strfreev(splitMessage);
        }
    }
    debugGHashTable(uriElements);
}   

/*
 * Function deleteAllUriHashTable
 * Delete all elements from hashtable,
 * destroy hashtable after deletion of elements
 */ 
void deleteAllUriHashTable(GHashTable* uriElements)
{
    debugS("Inside delete all uri hash table");
    if (g_hash_table_size(uriElements) == 0) 
    { 
        debugS("Nothing in HASHTABLE!");
        return; 
    }
    GHashTableIter elementIterator;
    g_hash_table_iter_init(&elementIterator, uriElements);
    gpointer hashKey, hashValue;  //gpointer used because expecting void**
    while(g_hash_table_iter_next(&elementIterator, &hashKey, &hashValue))
    {
        if (hashKey != NULL && hashValue != NULL)
        {
            g_free(hashKey);
            g_free(hashValue);
        }
    }
    g_hash_table_destroy(uriElements);
}

/*
 * Function keyToValueFromHashtable
 * g_hash_table_lookup() did not work
 * best to iterate and find key
 */
 gchar* keyToValueFromHashtable(GHashTable* uriElements, gchar* key)
 {
    debugS("Inside key to value iterator");
    debugD("HashTable size = ", g_hash_table_size(uriElements));
    if (g_hash_table_size(uriElements) == 0) 
    { 
        debugS("Nothing in HASHTABLE!");
        return NULL; 
    }

    GHashTableIter elementIterator;
    g_hash_table_iter_init(&elementIterator, uriElements);
    gpointer hashKey, hashValue;
    while(g_hash_table_iter_next(&elementIterator, &hashKey, &hashValue))
    {
        if (g_strcmp0((gchar*) &hashKey, key))
        {
            return ((gchar*) hashValue);
        }
    } 
    debugS("Key to value iterator finished");
    return NULL;
 }