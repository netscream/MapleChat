#include "processing.h"

void command_user(gchar** command, struct userInformation* user, gchar* data)
{
    gchar* log_message = NULL;;

    if (data == NULL)
    {
        SSL_write(user->sslFd, "Empty password obtained\n", 24);
    }
    else if(user->count_logins >= 2)
    {
        /* Disconnect user for trying too many times */
        SSL_write(user->sslFd,
                "Too many wrong tries. Closing connection\n",
                strlen("Too many wrong tries. Closing connection\n"));
        disconnect_user(user);
    }
    else if(user_authenticate(command[1], data))
    {
        log_message = g_strconcat(command[1], " authenticated", NULL);
        log_to_console(user->client, log_message);
        gchar* usern = g_strdup(command[1]);
        user->username = usern;
        if (user->nickname == NULL)
        {
            user->nickname = usern;
        }
        user->count_logins = 0;
        g_tree_insert(usersOnServerList, user->username, user);
    }
    else
    {
        log_message = g_strconcat(command[1], " authentication error", NULL);
        log_to_console(user->client, log_message);
        user->count_logins++;
    }
    if(log_message != NULL)
    {
        g_free(log_message);
    }
}

void command_list(struct userInformation* user)
{
    debug_s("User requested list of chat rooms\n");
    gchar* list_of_chans = g_strdup("");
    g_tree_foreach(roomsOnServerList, (GTraverseFunc) iter_rooms, (gpointer) &list_of_chans);
    if (g_strcmp0("", list_of_chans) != 0)
    {
        debug_s(list_of_chans);
        gchar* tmp = g_strconcat("Channels on server: ", list_of_chans, "\n", NULL);
        g_free(list_of_chans);
        SSL_write(user->sslFd, tmp, strlen(tmp));
    }
}

void command_join(gchar** command, struct userInformation* user)
{
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
            //gchar* tmp = g_strdup(tmp_room->room_name);
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
        room->user_list = g_list_append(room->user_list, user);
    }
    user->current_room = (struct room_information*) room;
    debug_s(user->current_room->room_name);
    debug_s(room->room_name);
    printf("joined this room, %s\n",command[1]);
}

void command_who(struct userInformation* user)
{
    debug_s("User requested list of users\n");
    gchar* list_of_users = g_strdup("");
    //g_tree_foreach(usersOnServerList, (GTraverseFunc) iter_users, (gpointer) &list_of_users);
    g_tree_foreach(connectionList, (GTraverseFunc) iter_users, (gpointer) &list_of_users);
    if (g_strcmp0("", list_of_users) != 0)
    {
        debug_s(list_of_users);
        gchar* tmp = g_strconcat("Users on server: \n", list_of_users, "\n", NULL);
        g_free(list_of_users);
        SSL_write(user->sslFd, tmp, strlen(tmp));
    }
}

void command_private_message(gchar** command, struct userInformation* user, gchar* data)
{
    debug_s("User sending private message\n");
    struct communication_message tmp;
    tmp.from_user = (gchar*) user->username;
    tmp.to_user = command[1];
    tmp.message = data;
    g_tree_foreach(usersOnServerList, (GTraverseFunc) iter_users_privmsg, (gpointer) &tmp);
}

void channel_send_message(struct userInformation* user, gchar* data)
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

void process_message(char* message, struct userInformation* user)
{
    gchar** msg = g_strsplit(message, ":", 0);
    gchar* data = msg[1];

    gchar** command = g_strsplit(msg[0], " ", 0);
    if ((g_strcmp0("USER", command[0]) != 0) && user->username == NULL)
    {
        SSL_write(user->sslFd,
                "User needs to be authenticated to user server\n",
                strlen("User needs to be authenticated to user server\n"));
        return;
    }

    if(g_strcmp0("USER", command[0]) == 0)
    {
        command_user(command, user, data);
    }
    else if(g_strcmp0("LIST", command[0]) == 0)
    {
        command_list(user);
    }
    else if(g_strcmp0("PRIVMSG", command[0]) == 0)
    {
        command_private_message(command, user, data);
    }
    else if(g_strcmp0("JOIN", command[0]) == 0)
    {
        command_join(command, user);
    }
    else if(g_strcmp0("WHO", command[0]) == 0)
    {
        command_who(user);
    }
    else /* lets assume everything else is a message to channel */
    {
        channel_send_message(user, data);
    }

    g_strfreev(msg);
    g_strfreev(command);
}
