#include "debugging.h"

/* 
 * Function to print time to output
 */
void print_time()
{
    char buffer[13];
    time_t timer = time(NULL); 
    struct tm *loctime;
    loctime = localtime(&timer);
    strftime(buffer, 13, "[%T]", loctime);
    fputs(buffer, stdout);
}
/*  Void function() for debugging
    Print string
*/
void debug_s(char* message)
{
    if (debug)
    {
        print_time();
        fprintf(stdout, "[Debug] %s\n", message);
    }
    fflush(stdout);
}

/*
 * void Function debugTwoS
 * For debugging 2 values from strings
 */
void debug_two_s(char* output_message, char* output_value)
{
    if (debug)
    {
        print_time();
        fprintf(stdout, "[Debug] %s=%s\n", output_message, output_value);
    }
    fflush(stdout);
}

/* void function() 
 * for debugging decimal 
 */
void debug_d(char* message, int id)
{
    if (debug)
    {
        print_time();
        fprintf(stdout, "[Debug] %s %d\n", message, id);
    }
    fflush(stdout);
}

/* void function() 
 * for debugging hex 
 */
void debug_sockaddr(char* message, struct sockaddr_in client_addr)
{
    if (debug)
    {
        int len = 20;
        char cl_bugg[len];
        print_time();
        fprintf(stdout, "[Debug] %s %s\n", message, inet_ntop(AF_INET, &(client_addr.sin_addr), cl_bugg, len));
        print_time();
        if (message[0] == 'S' || message[0] == 's')
        {
            printf("[Debug] Server port = %d\n", ntohs(client_addr.sin_port));
        }
        else
        {
            printf("[Debug] Client port = %d\n", ntohs(client_addr.sin_port));
        }
        fflush(stdout);
    }
}
/* void debugMessage()
 * for debugging messages in TFTP server
 */
void debug_message(char* message, size_t m_size)
{   
    if (debug)
    {
        print_time();
        printf("[Debug] ");
        for(size_t i = 0; i < m_size; i++)
        {
            printf("%c", message[i]);
        }
        printf(" of size = %lu", m_size);
        printf("\n");
    } 
}

/*
 * function debugGMessage
 * For debugging of double pointer message from glib
 */
void debug_gmessage(gchar** message, size_t m_size)
{   
    if (debug)
    {
        if (message != NULL)
        {
            print_time();
            printf("[Debug] \n");
            for(size_t i = 0; i < m_size; i++)
            {
                printf("%s\n", message[i]);
                //g_assert(g_printf("%s", message[i]));
            }
            printf("\n of size = %lu", m_size);
            printf("\n");
        }
    } 
}

/*
    Debugging done
*/