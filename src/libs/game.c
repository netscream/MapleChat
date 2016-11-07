#include "game.h"

void play_game(struct game* new_game, struct userInformation* user1, struct userInformation* user2)
{
	if (new_game == NULL)
	{
		new_game = g_new0(struct game, 1);
		new_game->player1 = user1;
		new_game->player2 = user2;
		new_game->p1 = 0;
		new_game->p2 = 0;
		new_game->acceptance = 0;
		gchar* tmp = g_strconcat("You have been challenged to a game of Dice by ", NULL);
		SSL_write(new_game->player1->sslFd, tmp, strlen(tmp));
	}
	else
	{
		gchar* tmp = NULL;
		if (strncmp(user1->nickname, new_game->player1->nickname, strlen(user1->nickname)) == 0)
		{
			tmp = g_strconcat("You are playing against user:", new_game->player2, "\n", "If you want to quit that game write /stopplay\n", NULL);
		}
		else
		{
			tmp = g_strconcat("You are playing against user:", new_game->player1, "\n", "If you want to quit that game write /stopplay\n", NULL);
		}
		SSL_write(new_game->player1->sslFd, tmp, strlen(tmp));
		g_free(tmp);
		return;
	}
	
}

void roll_dice(struct game* new_game)
{
	if (new_game->acceptance)
	{
		new_game->p1 = ROLL_DICE();
		new_game->p2 = ROLL_DICE();

		gchar* winner_message = NULL;
		if (new_game->p1 > new_game->p2)
		{
			winner_message = g_strconcat(new_game->player1->nickname, " WINS with the number ", (gchar) (new_game->p1+48), "\n",  new_game->player2->nickname, " LOOSES with the number ", (gchar) (new_game->p2+48), "\n", NULL);
		}
		else
		if (new_game->p1 < new_game->p2)
		{
			winner_message = g_strconcat(new_game->player2->nickname, " WINS with the number ", (gchar) (new_game->p2+48), "\n",  new_game->player1->nickname, " LOOSES with the number ", (gchar) (new_game->p1+48), "\n", NULL);
		}
		else
		{
			winner_message = g_strconcat(new_game->player1->nickname, " and ", new_game->player2->nickname, " are tied with ", new_game->p2, "\n", NULL);
		}
		SSL_write(new_game->player1->sslFd, winner_message, strlen(winner_message));
		SSL_write(new_game->player2->sslFd, winner_message, strlen(winner_message));
		new_game->player1->the_game = NULL;
		new_game->player2->the_game = NULL;
		new_game->player1 = NULL;
		new_game->player2 = NULL;
		g_free(new_game);
	}
	else
	{
		SSL_write(new_game->player1->sslFd, "No game on, challenge someone or wait for acceptance!", 32);
	}
}

void accept_play(struct game* new_game)
{
	new_game->acceptance = 1;
}

void reject_play(struct game* new_game)
{
	if (new_game != NULL)
	{
		g_free(new_game);
	}
}

void stop_play(struct game* new_game)
{
	reject_play(new_game);
}