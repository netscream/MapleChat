#ifndef PROCESSING_H
#define PROCESSING_H
#include "server.h"
#include "user.h"

void command_user(gchar** command, struct userInformation* user, gchar* data);
void command_list(gchar** command, struct userInformation* user);
void command_join(gchar** command, struct userInformation* user);
void command_private_message(gchar** command, struct userInformation* user, gchar* data);
void command_who(gchar** command, struct userInformation* user);
void channel_send_message(gchar** command, struct userInformation* user, gchar* data);
void process_message(char* message, struct userInformation* user);

#endif
