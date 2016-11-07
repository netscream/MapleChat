#include "authentication.h"
gchar* generate_salt()
{
    debug_s("Generating new salt");
    gchar* salt = g_new0(gchar, 10);
    for( int i = 0; i < 9; ++i)
    {
        salt[i] = '0' + rand()%72; // starting on '0', ending on '}'
    }
    salt[9] = '\0';
    return salt;
}

gchar* user_get_salt(gchar* username)
{
    debug_s("Getting password salt");
    gchar *salt = g_key_file_get_string(keyfile, "salts",
            username, NULL);

    if( salt == NULL )
    {
        return NULL;
    }

    return salt;
}

gchar* user_get_hash(gchar* username)
{
    debug_s("Getting password hash");
    gchar *passwd64 = g_key_file_get_string(keyfile, "passwords",
            username, NULL);

    if( passwd64 == NULL )
    {
        return NULL;
    }

    gsize length;
    gchar *passwd = (gchar*) g_base64_decode(passwd64, &length);

    g_free(passwd64);
    return passwd;
}

gchar* user_hash_password(gchar* passwd, gchar* salt)
{
    debug_s("Hashing user password");

    gchar* hash = g_new0(gchar, SHA256_DIGEST_LENGTH);

    gchar* password = g_strconcat(passwd, salt, NULL);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final((guchar*) hash, &sha256);

    g_free(password);
    return hash;
}

void user_set_hash(gchar* username, gchar* passwd)
{
    gchar* salt = generate_salt();

    gchar* hash = user_hash_password(passwd, salt);

    debug_s("Setting password hash");
    gchar *hash64 = (gchar*) g_base64_encode((guchar*) hash, strlen(hash));
    g_key_file_set_string(keyfile, "passwords", username, hash64);
    g_key_file_set_string(keyfile, "salts", username, salt);
    g_key_file_save_to_file(keyfile, "passwords.ini", NULL);

    g_free(hash);
    g_free(salt);
    g_free(hash64);
}
