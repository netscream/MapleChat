#include "game.h"
/*
 * Function play game
 * used to play a game against other users
 */
void play_game(struct game* new_game, struct userInformation* user1, struct userInformation* user2)
{
    gchar* tmp = NULL;
    debug_s("Playing game");
    if (new_game == NULL)
    {
        debug_s("new game is not null");
        new_game = g_new0(struct game, 1);
        new_game->player1 = user1;
        new_game->player2 = user2;
        new_game->p1 = 0;
        new_game->p2 = 0;
        new_game->acceptance = 0;
        user1->the_game = new_game;
        user2->the_game = new_game;
        debug_s("Next concat a line to send");
        tmp = g_strconcat("You have been challenged to a game of Dice by ", NULL);
        SSL_write(new_game->player2->sslFd, tmp, strlen(tmp));
    }
    else
    {
        debug_s("new game is null");
        if (strncmp(user1->nickname, new_game->player1->nickname, strlen(user1->nickname)) == 0)
        {
            tmp = g_strconcat("You are playing against user:", new_game->player2, "\n", "If you want to quit that game write /stopplay\n", NULL);
        }
        else
        {
            tmp = g_strconcat("You are playing against user:", new_game->player1, "\n", "If you want to quit that game write /stopplay\n", NULL);
        }
        SSL_write(new_game->player1->sslFd, tmp, strlen(tmp));
        return;
    }

    g_free(tmp);

}

/*
 * Function roll dice
 * used to roll the dice for the players of the game
 */
void roll_dice(struct game* new_game)
{
    if (new_game != NULL)
    {
        if (new_game->acceptance)
        {
            new_game->p1 = ROLL_DICE();
            new_game->p2 = ROLL_DICE();
            debug_s("ROLLING worked");
            gchar* winner_message = NULL;
            char p1_number[2];
            char p2_number[2];
            sprintf(p1_number, "%d", new_game->p1);
            sprintf(p2_number, "%d", new_game->p2);
            if (new_game->p1 > new_game->p2)
            {
                winner_message = g_strconcat(new_game->player1->nickname, " WINS with the number ", p1_number, "\n",  new_game->player2->nickname, " LOOSES with the number ", p2_number, "\n", NULL);
            }
            else
                if (new_game->p1 < new_game->p2)
                {
                    winner_message = g_strconcat(new_game->player2->nickname, " WINS with the number ", p2_number, "\n",  new_game->player1->nickname, " LOOSES with the number ", p1_number, "\n", NULL);
                }
                else
                {
                    winner_message = g_strconcat(new_game->player1->nickname, " and ", new_game->player2->nickname, " are tied with ", p2_number, "\n", NULL);
                }
            SSL_write(new_game->player1->sslFd, winner_message, strlen(winner_message));
            SSL_write(new_game->player2->sslFd, winner_message, strlen(winner_message));
            g_free(winner_message);

            new_game->player1->the_game = NULL;
            new_game->player2->the_game = NULL;
            new_game->player1 = NULL;
            new_game->player2 = NULL;
            g_free(new_game);
        }
    }
}

/*
 * Function accept play
 * used to accept game play from other players
 */
void accept_play(struct game* new_game)
{
    gchar* tmp = g_strconcat("Player ", new_game->player2->nickname, " has accepted your challenge", NULL);
    SSL_write(new_game->player1->sslFd, tmp, strlen(tmp));
    g_free(tmp);
    new_game->acceptance = 1;
}

/*
 * Function reject play
 * used to reject a play from other users
 */
void reject_play(struct game* new_game)
{
    if (new_game != NULL)
    {
        gchar* tmp = g_strconcat("Player ", new_game->player2, " has rejected your challenge", NULL);
        SSL_write(new_game->player1->sslFd, tmp, strlen(tmp));
        g_free(tmp);
        g_free(new_game);
    }
}

/*
 * Function stop play
 * used to stop playing a game if the other user has not accepted or rejected
 */
void stop_play(struct game* new_game)
{
    reject_play(new_game);
}

/*
 * Function roll dice
 * used to roll the dice for each user
 */
int ROLL_DICE()
{
    return (int) floor(drand48() * 6.0) + 1;
}
