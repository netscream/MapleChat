#ifndef USER_H
#define USER_H
#include "server.h"
#include "authentication.h"
int user_authenticate(gchar* username, gchar* passwd);
void disconnect_user(struct userInformation* user);

#endif
