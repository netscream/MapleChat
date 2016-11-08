#ifndef ITERATORS_H
#define ITERATORS_H
#include "server.h"
/* All function comments are in c file */

gboolean iter_connections(gpointer key, gpointer value, gpointer data);
gboolean iter_check_timeout(gpointer key, gpointer value, gpointer data);
gboolean iter_ping(gpointer key, gpointer value, gpointer data);
gboolean iter_add_to_fd_set(gpointer key, gpointer value, gpointer data);
gboolean iter_users(gpointer key, gpointer value, gpointer data);
gboolean iter_rooms(gpointer key, gpointer value, gpointer data);
gboolean iter_users_privmsg(gpointer key, gpointer value, gpointer data);
gboolean iter_users_find(gpointer key, gpointer value, gpointer data);
#endif
