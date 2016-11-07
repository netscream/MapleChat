#ifndef GAME_H
#define GAME_H
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <glib.h>
#include "structures.h"

inline int ROLL_DICE() { return ((int) floor(drand48() * 6.0) + 1); }

void play_game(struct game* new_game, struct userInformation* user1, struct userInformation* user2);
void roll_dice(struct game* new_game);
void accept_play(struct game* new_game);
void reject_play(struct game* new_game);
void stop_play(struct game* new_game);
#endif