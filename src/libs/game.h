#ifndef SERVER_H
#define SERVER_H
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <glib.h>
#include "server.h"
inline int ROLL_DICE() { return ((int) floor(drand48() * 6.0) + 1); }

struct game{
	struct userInformation* player1;
	struct userInformation* player2;

	int p1;
	int p2;

	int acceptance;	
};

void play_game(struct game* new_game, struct userInformation* user1, struct userInformation* user2);
void roll_dice(struct game* new_game);
void accept_play(struct game* new_game);
void stop_play(struct game* new_game);
#endif