#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H
#include "server.h"
/* All function comments are in c file */

gchar* generate_salt();
gchar* user_get_salt(gchar* username);
gchar* user_get_hash(gchar* username);
gchar* user_hash_password(gchar* passwd, gchar* salt);
void user_set_hash(gchar* username, gchar* passwd);

#endif
