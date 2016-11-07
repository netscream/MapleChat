#include "user.h"

int user_authenticate(gchar* username, gchar* passwd)
{
    debug_s("Authenticating user");
    gchar* stored_hash = user_get_hash(username);
    if(stored_hash == NULL)
    {
        debug_s("Creating new user");
        /* New user, hash his password and store it */
        user_set_hash(username, passwd);
        g_free(stored_hash);
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
    g_free(stored_hash);
    return 0;
}

void disconnect_user(struct userInformation* user)
{
    debug_s("Disconnecting user");
    g_tree_steal(connectionList, &user->fd);

    if (user->username != NULL)
    {
        free(user->username);
    }
    if (user->the_game != NULL)
    {
        struct game* tmp = user->the_game;
        tmp->player1->the_game = NULL;
        tmp->player2->the_game = NULL;
        g_free(tmp);
    }
    close(user->fd);
    SSL_free(user->sslFd);
    g_free(user->client);
    g_free(user);
}