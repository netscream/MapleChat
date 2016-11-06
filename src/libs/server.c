#include "server.h"

gchar* generate_salt()
{
    debug_s("Generating new salt");
    gchar* salt = g_new0(gchar, 10);
    for( int i = 0; i < 9; ++i)
    {
        salt[i] = '0' + rand()%72; // starting on '0', ending on '}'
    }
    salt[9] = '\0';
    return salt;
}

gchar* user_get_salt(gchar* username)
{
    debug_s("Getting password salt");
    GError* error = NULL;
    gchar *salt = g_key_file_get_string(keyfile, "salts",
            username, &error);

    if( salt == NULL )
    {
        return NULL;
    }

    return salt;
}

gchar* user_get_hash(gchar* username)
{
    debug_s("Getting password hash");
    GError* error = NULL;
    gchar *passwd64 = g_key_file_get_string(keyfile, "passwords",
            username, &error);

    if( passwd64 == NULL )
    {
        return NULL;
    }

    gsize length;
    gchar *passwd = g_base64_decode(passwd64, &length);
    return passwd;
}

gchar* user_hash_password(gchar* passwd, gchar* salt)
{
    debug_s("Hashing user password");

    gchar* hash = g_new0(gchar, SHA256_DIGEST_LENGTH);

    gchar* password = g_strconcat(passwd, salt, NULL);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);

    g_free(password);
    return hash;
}

void user_set_hash(gchar* username, gchar* passwd)
{
    gchar* salt = generate_salt();

    gchar* hash = user_hash_password(passwd, salt);

    debug_s("Setting password hash");
    gchar *hash64 = g_base64_encode(hash, strlen(hash));
    g_key_file_set_string(keyfile, "passwords", username, hash64);
    g_key_file_set_string(keyfile, "salts", username, salt);
    g_key_file_save_to_file(keyfile, "passwords.ini", NULL);

    g_free(hash);
    g_free(salt);
    g_free(hash64);
}

int user_authenticate(gchar* username, gchar* passwd)
{
    debug_s("Authenticating user");
    gchar* stored_hash = user_get_hash(username);
    if(stored_hash == NULL)
    {
        debug_s("Creating new user");
        /* New user, hash his password and store it */
        user_set_hash(username, passwd);
        return 1;
    }
    else
    {
        int authenticated = 0;
        debug_s("Checking password");
        /* Check if the given password matches the hash */

        gchar* salt = user_get_salt(username);
        gchar* hash = user_hash_password(passwd, salt);

        if(g_strcmp0(hash, stored_hash) == 0)
        {
            debug_s("Password is correct");
            /* Authenticated */
            authenticated = 1;
        }
        else
        {
            debug_s("Password is incorrect");
            /* Failed, can only happen 3 times until disconnect */
            authenticated = 0;
        }

        g_free(salt);
        g_free(stored_hash);
        g_free(hash);
        return authenticated;
    }

    return 0;
}

void process_message(char* message, struct userInformation* user)
{
    gchar** msg = g_strsplit(message, ":", 0);
    gchar* data = msg[1];

    gchar** command = g_strsplit(msg[0], " ", 0);

    if(g_strcmp0("USER", command[0]) == 0)
    {
        if (data == NULL)
        {
            SSL_write(user->sslFd, "Empty password obtained\n", 24);
        }
        else
        if(user_authenticate(command[1], data))
        {
            printf("User logged in as %s\n", command[1]);
            gchar* usern = g_strdup(command[1]);
            user->username = usern;
            if (user->nickname == NULL)
            {
                user->nickname = usern;
            }
            user->count_logins++;
            g_tree_insert(usersOnServerList, user->username, user);
        }
        else
        {
            printf("Incorrect password for %s\n", command[1]);
        }
    }
    else if(g_strcmp0("LIST", command[0]) == 0)
    {
        debug_s("User requested list of chat rooms\n");
        gchar* list_of_chans = g_strdup("");
        g_tree_foreach(roomsOnServerList, (GTraverseFunc) iter_rooms_or_users, (gpointer) &list_of_chans);
        if (g_strcmp0("", list_of_chans) != 0)
        {
            debug_s(list_of_chans);
            gchar* tmp = g_strconcat("Channels on server: ", list_of_chans, "\n", NULL);
            g_free(list_of_chans);
            SSL_write(user->sslFd, tmp, strlen(tmp));
        }

    }
    else if(g_strcmp0("JOIN", command[0]) == 0){
        debug_s("user wants to join ");
        if(user->current_room != NULL)
        {
            struct room_information* tmp_room = user->current_room;
            printf("g_list length = %d\n", g_list_length(tmp_room->user_list));
            tmp_room->user_list = g_list_remove(tmp_room->user_list, user);
            printf("g_list length = %d\n", g_list_length(tmp_room->user_list));
            if (g_list_length(tmp_room->user_list) == 0)
            {
                g_list_free(tmp_room->user_list);
                gchar* tmp = g_strdup(tmp_room->room_name);
                g_tree_remove(roomsOnServerList, tmp_room->room_name);
                g_free(tmp_room->room_name);
                g_free(tmp_room);
            }
            user->current_room = NULL;
            debug_s("Old room removed \n");
        }
        
        printf("joining this room  %s\n",command[1]);
        RoomI *room = NULL;
        debug_s(command[1]);
        room = g_tree_lookup(roomsOnServerList, (gchar*) command[1]);
        debug_s("Done looking \n");
        if(room  == NULL)
        {
            room = g_new0(RoomI,1);
            room->room_name = g_strdup(command[1]);
            room->user_list = g_list_append(room->user_list, user);
            debug_s("new room created  \n");
            g_tree_insert(roomsOnServerList, (gchar*) room->room_name, room);
            debug_s("done creating/found room \n");
        }
        else
        {
            //printf("g_list length = %d\n", g_list_length(room->user_list));
            room->user_list = g_list_append(room->user_list, user);
            //printf("g_list length = %d\n", g_list_length(room->user_list));
        }
        user->current_room = (struct room_information*) room;
        debug_s(user->current_room->room_name);
        debug_s(room->room_name);
        printf("joined this room, %s\n",command[1]);

    }
    else if(g_strcmp0("WHO", command[0]) == 0)
    {
        debug_s("User requested list of users\n");
        gchar* list_of_users = g_strdup("");
        g_tree_foreach(usersOnServerList, (GTraverseFunc) iter_rooms_or_users, (gpointer) &list_of_users);
        if (g_strcmp0("", list_of_users) != 0)
        {
            debug_s(list_of_users);
            gchar* tmp = g_strconcat("Users on server: ", list_of_users, "\n", NULL);
            g_free(list_of_users);
            SSL_write(user->sslFd, tmp, strlen(tmp));
        }
    }
    else if(g_strcmp0("PRIVMSG", command[0]) == 0)
    {
        debug_s("User sending private message\n");
        struct communication_message tmp;
        tmp.from_user = (gchar*) user->username;
        tmp.to_user = command[1];
        tmp.message = data;
        g_tree_foreach(usersOnServerList, (GTraverseFunc) iter_users_privmsg, (gpointer) &tmp);
    }
    else /* lets assume everything else is a message to channel */
    {
        debug_s("User sending message to channel\n");
        struct room_information* user_room = user->current_room;
        if (user_room != NULL)
        {
            debug_s("User room is not NULL");
            gchar* send_message = g_strconcat(user_room->room_name, " ", "<", user->nickname ,">:", data, NULL);
            GList *tmp = user_room->user_list;
            while (tmp != NULL)
            {
                struct userInformation* tmpUser = NULL;
                tmpUser = tmp->data;
                if (tmpUser != NULL)
                {
                    debug_s(tmpUser->nickname);
                    SSL_write(tmpUser->sslFd, send_message, strlen(send_message));
                }
                tmp = g_list_next(tmp);
            }
            g_free(send_message);
        }
        else
        {
            SSL_write(user->sslFd, "User not in channel\n", 20);
        }
    }

    g_strfreev(msg);
    g_strfreev(command);
}

gboolean gstring_is_equal(const gpointer a, const gpointer b)
{

    if (g_strcmp0((gchar*)a, (gchar*)b) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
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
        process_message(message , (struct userInformation*) user);
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

gboolean iter_rooms_or_users(gpointer key, gpointer value, gpointer data)
{
    if (key != NULL && value != NULL)
    {
        if (g_strcmp0("", *((gchar**) data)) == 0)
        {
            g_free(*((gchar**) data));
            *((gchar**) data) = (gpointer) g_strdup((gchar*) key);
        }
        else
        {
            gchar* tmp = g_strjoin(",", *((gchar**) data), (gchar*) key, NULL);
            g_free(*((gchar**) data));
            *((gchar**) data) = (gpointer) tmp;
        }
    }
    return 0;
}

gboolean iter_users_privmsg(gpointer key, gpointer value, gpointer data)
{
    gchar* to_user = ((struct communication_message*) data)->to_user;
    debug_s(to_user);
    if (g_strcmp0((gchar*) to_user, (gchar*) key) == 0)
    {
        UserI* temp = (UserI*) value;
        gchar* send_string = g_strconcat("Privmsg from ", ((struct communication_message*) data)->from_user, " => ", ((struct communication_message*) data)->message, NULL);
        debug_s(send_string);
        SSL_write(temp->sslFd, send_string, strlen(send_string));
        g_free(send_string);
        return 1;
    }
    return 0;
}
/*
 * Function runServer
 * The main server function
 * Creates a loop for the server run
 */
int run_server(int port_num)
{
    int sockFd = -1, max_fd = 0;
    struct  sockaddr_in server;
    SSL_CTX* theSSLctx;
    int opt = 1;

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
    sockFd = initalize_server(port_num, server);
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
                    debug_s("STUFF");
                    UserI *new_user = g_new0(UserI, 1); //create new User struct
                    initialize_user_struct(new_user);
                    new_user->sslFd = sslclient;
                    new_user->fd = clientSockFd;
                    g_tree_insert(connectionList, &new_user->fd, new_user);
                    if (SSL_write(sslclient, "Server: Welcome!", 16) == -1)
                    {
                        debug_s("SSL_WRITE error:");
                        ERR_print_errors_fp(stderr);
                    }
                    log_to_console(&client, "connected");
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

        debug_s("Processing clients");
        /* TODO: Iterate through all of the clients and check if */
        /* their socket is active */
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
int initalize_server(const int port_num, struct sockaddr_in server)
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
    return 0;
}

/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer user1,  gconstpointer user2, gpointer G_GNUC_UNUSED data)
{
    return GPOINTER_TO_INT(((UserI*) user1)->fd) - GPOINTER_TO_INT(((UserI*) user2)->fd);
}

/*gint room_name_cmp(gconstpointer A,  gconstpointer B, gpointer G_GNUC_UNUSED data)
{
    return g_strcmp0(((struct room_information*) A)->room_name, ((struct room_information*)B)->room_name);
}*/

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

void initialize_user_struct(struct userInformation *new_user)
{
    new_user->sslFd = NULL;
    new_user->fd = -1;
    new_user->username = NULL;
    new_user->nickname = NULL;
    new_user->roomname = NULL;
    new_user->count_logins = 0;
    new_user->login_timeout = 0;
}

int send_to_user_message(struct userInformation user, char* message)
{
    return 0;
}
