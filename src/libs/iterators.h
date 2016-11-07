#ifndef ITERATORS_H
#define ITERATORS_H
#include "server.h"
gboolean iter_connections(gpointer key, gpointer value, gpointer data);
gboolean iter_live_connections(gpointer key, gpointer value, gpointer data);
gboolean iter_add_to_fd_set(gpointer key, gpointer value, gpointer data);
gboolean iter_users(gpointer key, gpointer value, gpointer data);
gboolean iter_rooms(gpointer key, gpointer value, gpointer data);
gboolean iter_users_privmsg(gpointer key, gpointer value, gpointer data);
gboolean iter_users_find(gpointer key, gpointer value, gpointer data);
#endif
