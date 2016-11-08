#ifndef PROCESSING_H
#define PROCESSING_H
#include "structures.h"
#include "user.h"
#include "game.h"

/* All function comments are in c file */
void command_user(gchar** command, struct userInformation* user, gchar* data);
void command_list(struct userInformation* user);
void command_join(gchar** command, struct userInformation* user);
void command_private_message(gchar** command, struct userInformation* user, gchar* data);
void command_who(struct userInformation* user);
void channel_send_message(struct userInformation* user, gchar* data);
void command_play(struct userInformation* user, gchar* data);
void command_accept(struct userInformation* user);
void command_reject(struct userInformation* user);
void command_roll(struct userInformation* user);
void process_message(char* message, struct userInformation* user);
#endif
