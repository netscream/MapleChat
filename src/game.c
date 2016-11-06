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
		gchar* tmp = g_strconcat("You have been challenged to a game of Dice by ",, NULL);
		SSL_write(new_game->player1->sslFd, tmp, strlen(tmp));
	}
	else
	{
		gchar* tmp = g_strconcat("You are playing against user:", new_game->player2, "\n", "If you want to quit that game write /stopplay\n", NULL);
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
	}
}

void accept_play(struct game* new_game)
{
	new_game->acceptance = 1;
}

void reject_play(struct game* new_game)
{
	g_free(new_game);
}

void stop_play(struct game* new_game)
{
	reject_play(new_game);
}

gchar* return_message(struct game* new_game)
{
	if (new_game->p1 > new_game->p2)
	{
		return "";
	}
	else
	{
		return "";
	}
}