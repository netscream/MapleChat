#include "processing.h"

/*
 * Function command user
 * used for doing user logging processing
 */
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
        SSL_write(user->sslFd, "Authenticated", 13);
    }
    else
    {
        log_message = g_strconcat(command[1], " authentication error", NULL);
        log_to_console(user->client, log_message);
        user->count_logins++;
        SSL_write(user->sslFd, "Auth Error", 14);
    }
    if(log_message != NULL)
    {
        g_free(log_message);
    }
}

/*
 * Function command list
 * used for processing the list command
 */
void command_list(struct userInformation* user)
{
    debug_s("User requested list of chat rooms\n");
    gchar* list_of_chans = g_strdup("");
    g_tree_foreach(roomsOnServerList, (GTraverseFunc) iter_rooms, (gpointer) &list_of_chans);
    if (g_strcmp0("", list_of_chans) != 0)
    {
        debug_s(list_of_chans);
        gchar* tmp = g_strconcat("Channels on server: ", list_of_chans, "\n", NULL);
        SSL_write(user->sslFd, tmp, strlen(tmp));
        g_free(tmp);
    }
    g_free(list_of_chans);
}

/*
 * Function command join
 * used for processing the join command
 */
void command_join(gchar** command, struct userInformation* user)
{
    debug_s("user wants to join ");
    if(user->current_room != NULL)
    {
        struct room_information* tmp_room = user->current_room;
        /* printf("g_list length = %d\n", g_list_length(tmp_room->user_list)); */
        tmp_room->user_list = g_list_remove(tmp_room->user_list, user);
        /* printf("g_list length = %d\n", g_list_length(tmp_room->user_list)); */
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

    /* printf("joining this room  %s\n",command[1]); */
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
    /* printf("joined this room, %s\n",command[1]); */
    SSL_write(user->sslFd, " ", 1);
}

/*
 * Function command who
 * used for who command processing
 */
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
        SSL_write(user->sslFd, tmp, strlen(tmp));
        g_free(tmp);
    }
    g_free(list_of_users);
}

/*
 * Function command private message
 * used for private message processing
 */
void command_private_message(gchar** command, struct userInformation* user, gchar* data)
{
    debug_s("User sending private message\n");
    struct communication_message tmp;
    tmp.from_user = (gchar*) user->username;
    tmp.to_user = command[1];
    tmp.message = data;
    g_tree_foreach(usersOnServerList, (GTraverseFunc) iter_users_privmsg, (gpointer) &tmp);
}

/*
 * Function command send message
 * used for processing messages to a channel
 */
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

/*
 * Function command play
 * used for processing the play command from user
 */
void command_play(struct userInformation* user, gchar* data)
{
    struct find_user tmp;
    tmp.user1 = user;
    tmp.user2 = NULL;
    tmp.stringuser2 = data;

    g_tree_foreach(usersOnServerList, (GTraverseFunc) iter_users_find, (gpointer) &tmp);
    if (tmp.user2 != NULL)
    {
        debug_s("User 2 is not null");
        struct userInformation* user2 = (struct userInformation*) tmp.user2;
        if (g_strcmp0(user->nickname, user2->nickname) == 0)
        {
            SSL_write(user->sslFd, "Cannot play with yourself!", 26);
        }
        else
        {
            struct game *new_game = NULL;
            play_game(new_game, user, user2);
        }
    }
    else
    {
        SSL_write(user->sslFd, "No such user found!", 19);
    }
}

/*
 * Function command accept
 * used to process accept for game play from user
 */
void command_accept(struct userInformation* user)
{
    if (user->the_game == NULL)
    {
        SSL_write(user->sslFd, "No game running\n", 17);
    }
    else
    {
        accept_play(user->the_game);
    }
}

/*
 * Function command reject
 * used to process reject command from user
 */
void command_reject(struct userInformation* user)
{
    if (user->the_game == NULL)
    {
        SSL_write(user->sslFd, "No game running\n", 17);
    }
    else
    {
        reject_play(user->the_game);
    }
}

/*
 * Function command roll
 * used for process roll command from user
 */
void command_roll(struct userInformation* user)
{
    roll_dice(user->the_game);
}

/*
 * Function process message
 * used for deciding which command to call from user message
 */
void process_message(char* message, struct userInformation* user)
{
    gchar** msg = g_strsplit(message, ":", 0);
    gchar* data = msg[1];

    gchar** command = g_strsplit(msg[0], " ", 0);

    if(g_strcmp0("QUIT", command[0]) == 0)
    {
        log_to_console(user->client, "disconnected");
        disconnect_user(user);
    }
    else if(g_strcmp0("PONG", command[0]) == 0)
    {
        debug_s("Recieved PONG");
        struct timeval now;
        gettimeofday(&now, NULL);
        user->login_timeout.tv_sec = now.tv_sec + (TIMEOUT_INTERVAL * 3);
    }
    else if ((g_strcmp0("USER", command[0]) != 0) && user->username == NULL)
    {
        /* If user is not authenticated he shouldn't be able to run the */
        /* subsequent commands */
        SSL_write(user->sslFd,
                "User needs to be authenticated to user server\n",
                strlen("User needs to be authenticated to user server\n"));
    }
    else if(g_strcmp0("USER", command[0]) == 0)
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
    else if(g_strcmp0("PLAY", command[0]) == 0)
    {
        command_play(user, command[2]);
    }
    else if(g_strcmp0("ACCEPT", command[0]) == 0)
    {
        command_accept(user);
    }
    else if(g_strcmp0("REJECT", command[0]) == 0)
    {
        command_reject(user);
    }
    else if(g_strcmp0("ROLL", command[0]) == 0)
    {
        command_roll(user);
    }
    else /* lets assume everything else is a message to channel */
    {
        channel_send_message(user, data);
    }

    g_strfreev(msg);
    g_strfreev(command);
}
