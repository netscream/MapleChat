#include "iterators.h"

/*
 * Function iter check timeout
 * used for iteration over gtree to check if user gets a timeout
 */
gboolean iter_check_timeout(gpointer key, gpointer value, gpointer data)
{
    if (data != NULL) { data = NULL; } //disable compile warnings
    if (key != NULL && value != NULL)
    {
        struct timeval now;
        UserI* user = (UserI* ) value;

        gettimeofday(&now, NULL);

        if(now.tv_sec > user->login_timeout.tv_sec)
        {
            log_to_console(user->client, "timed out.");
            disconnect_user(user);
        }
    }

    return 0;
}

/*
 * Function iter ping
 * used to iter over users and ping them to prevent timeout
 */
gboolean iter_ping(gpointer key, gpointer value, gpointer data)
{
    if (data != NULL) { data = NULL; } //disable compile warnings
    if (key != NULL && value != NULL)
    {
        UserI* user = (UserI* ) value;
        SSL_write(user->sslFd, "PING", sizeof("PING"));
    }

    return 0;
}

/*
 * Function iter connections
 * used for iteration over gtree to check if user has something on the line buffer
 */
gboolean iter_connections(gpointer key, gpointer value, gpointer data)
{
    if (key != NULL && value != NULL)
    {
        UserI* user = (UserI* ) value;

        if (FD_ISSET(*((int*) key), (fd_set *)data))
        {
            debug_d("Socket active No #", user->fd);
            char message[512];
            memset(message, 0, sizeof(message));
            SSL_read(user->sslFd, message, sizeof(message));
            debug_s("Message:");
            debug_s(message);
            if (message != NULL && strcmp(message, "") != 0)
            {
                process_message(message , (struct userInformation*) user);
            }
        }
        else
        {
            debug_d("Socket inactive No #", user->fd);
        }
    }
    return 0;
}

/*
 * Function iter add to fd set
 * used for iteration over gtree to add to the fd set for connection with select
 */
gboolean iter_add_to_fd_set(gpointer key, gpointer value, gpointer data)
{
    if (key != NULL && value != NULL)
    {
        UserI* user = (UserI* ) value;
        iterArgs* args = (iterArgs *) data;

        FD_SET(*((int*) key), args->readFdSet);

        if(user->fd > *(args->max_fd))
            *(args->max_fd) = user->fd;
    }

    return 0;
}

/*
 * Function iter users
 * used for iteration over gtree to see if user has received  message to some channel he is a part of
 */
gboolean iter_users(gpointer key, gpointer value, gpointer data)
{
    if (key != NULL && value != NULL)
    {
        if (g_strcmp0("", *((gchar**) data)) == 0)
        {
            struct userInformation* tmp_user = (struct userInformation*) value;
            if (tmp_user->username != NULL)
            {
                g_free(*((gchar**) data));
                *((gchar**) data) = (gpointer) g_strdup(tmp_user->username);
            }
            struct sockaddr_in* client_addr = tmp_user->client;
            char port_id[2];
            int len = 14;
            memset(&port_id, 0, 2);
            char cl_bugg[len];
            memset(&cl_bugg, 0, len);
            sprintf(port_id,"%d", ntohs(client_addr->sin_port));
            gchar* tmp = NULL;
            if (tmp_user->current_room != NULL)
            {
                debug_s("user is in chatroom");
                tmp = g_strjoin("", *((gchar**) data), "\t", "(",
                                inet_ntop(AF_INET, &(client_addr)->sin_addr, cl_bugg, len),
                                ":", port_id, ")", "\t" , tmp_user->current_room->room_name,
                                "\n", NULL);
            }
            else
            {
                tmp = g_strjoin("", *((gchar**) data), "\t", "(",
                                inet_ntop(AF_INET, &(client_addr)->sin_addr, cl_bugg, len),
                                ":", port_id, ")", "\t", "\n", NULL);
            }
            g_free(*((gchar**) data));
            *((gchar**) data) = (gpointer) tmp;
        }
        else
        {
            gchar* this_username = "\t";
            struct userInformation* tmp_user = (struct userInformation*) value;
            if (tmp_user->username != NULL)
            {
                this_username = tmp_user->username;
            }
            struct sockaddr_in* client_addr = tmp_user->client;
            char port_id[2];
            int len = 14;
            memset(&port_id, 0, 2);
            char cl_bugg[len];
            memset(&cl_bugg, 0, len);
            sprintf(port_id,"%d", ntohs(client_addr->sin_port));
            gchar* tmp = NULL;
            if (tmp_user->current_room != NULL)
            {
                debug_s("user is in chatroom");
                tmp = g_strjoin("", *((gchar**) data), this_username, "\t", "(",
                                inet_ntop(AF_INET, &(client_addr)->sin_addr, cl_bugg, len),
                                ":", port_id, ")", "\t" , tmp_user->current_room->room_name,
                                "\n", NULL);
            }
            else
            {
                tmp = g_strjoin("", *((gchar**) data), this_username, "\t", "(",
                                inet_ntop(AF_INET, &(client_addr)->sin_addr, cl_bugg, len),
                                ":", port_id, ")", "\t", "\n", NULL);
            }
            g_free(*((gchar**) data));
            *((gchar**) data) = (gpointer) tmp;
        }
        return 0;
    }
    return 0;
}

/*
 * Function iter rooms
 * used for iteration over gtree of all the rooms to make a list of all the rooms available 
 */
gboolean iter_rooms(gpointer key, gpointer value, gpointer data)
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

/*
 * Function iter user privmsg
 * used for iteration over gtree to check if user exists to get the private message
 */
gboolean iter_users_privmsg(gpointer key, gpointer value, gpointer data)
{
    if (key != NULL && value != NULL)
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
    }
    return 0;
}

/*
 * Function iter users find
 * used for iteration over gtree to check if user is existing
 */
gboolean iter_users_find(gpointer key, gpointer value, gpointer data)
{
    if (key != NULL && value != NULL)
    {
        gchar* find_this_user = ((struct find_user*) data)->stringuser2;

        if (g_strcmp0((gchar*) find_this_user, (gchar*) key) == 0)
        {
            debug_s("user found");
            struct find_user* tmp = (struct find_user*) data;
            tmp->user2 =  (struct userInformation*) value;
            debug_s("End of find user iter");
            return 1;
        }
    }
    return 0;
}
