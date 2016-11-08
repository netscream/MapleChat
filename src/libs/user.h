#ifndef USER_H
#define USER_H
#include "structures.h"
#include "authentication.h"
/* All function comments are in c file */
int user_authenticate(gchar* username, gchar* passwd);
void disconnect_user(struct userInformation* user);

#endif
