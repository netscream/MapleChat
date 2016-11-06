#ifndef PROCESSING_H
#define PROCESSING_H
#include "structures.h"
#include "user.h"


void command_user(gchar** command, struct userInformation* user, gchar* data);
void command_list(struct userInformation* user);
void command_join(gchar** command, struct userInformation* user);
void command_private_message(gchar** command, struct userInformation* user, gchar* data);
void command_who(struct userInformation* user);
void channel_send_message(struct userInformation* user, gchar* data);
void process_message(char* message, struct userInformation* user);

#endif
