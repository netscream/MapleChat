#ifndef GAME_H
#define GAME_H
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <glib.h>
#include "debugging.h"
#include "structures.h"
/* All function comments are in c file */

int ROLL_DICE();

void play_game(struct game* new_game, struct userInformation* user1, struct userInformation* user2);
void roll_dice(struct game* new_game);
void accept_play(struct game* new_game);
void reject_play(struct game* new_game);
void stop_play(struct game* new_game);
#endif