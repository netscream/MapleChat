#include "debugging.h"

/* 
 * Function to print time to output
 */
void printTime()
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
void debugS(char* message)
{
    if (deBug)
    {
        printTime();
        fprintf(stdout, "[Debug] %s\n", message);
    }
    fflush(stdout);
}

/*
 * void Function debugTwoS
 * For debugging 2 values from strings
 */
void debugTwoS(char* outputMessage, char* outputValue)
{
    if (deBug)
    {
        printTime();
        fprintf(stdout, "[Debug] %s=%s\n", outputMessage, outputValue);
    }
    fflush(stdout);
}

/* void function() 
 * for debugging decimal 
 */
void debugD(char* message, int id)
{
    if (deBug)
    {
        printTime();
        fprintf(stdout, "[Debug] %s %d\n", message, id);
    }
    fflush(stdout);
}

/* void function() 
 * for debugging hex 
 */
void debugSockAddr(char* message, struct sockaddr_in clientAddr)
{
    if (deBug)
    {
        int len = 20;
        char clBugg[len];
        printTime();
        fprintf(stdout, "[Debug] %s %s\n", message, inet_ntop(AF_INET, &(clientAddr.sin_addr), clBugg, len));
        printTime();
        if (message[0] == 'S')
        {
            printf("[Debug] Server port = %d\n", ntohs(clientAddr.sin_port));
        }
        else
        {
            printf("[Debug] Client port = %d\n", ntohs(clientAddr.sin_port));
        }
        fflush(stdout);
    }
}
/* void debugMessage()
 * for debugging messages in TFTP server
 */
void debugMessage(char* message, size_t mSize)
{   
    if (deBug)
    {
        printTime();
        printf("[Debug] ");
        for(size_t i = 0; i < mSize; i++)
        {
            printf("%c", message[i]);
        }
        printf(" of size = %lu", mSize);
        printf("\n");
    } 
}

/*
 * function debugGMessage
 * For debugging of double pointer message from glib
 */
void debugGMessage(gchar** message, size_t mSize)
{   
    if (deBug)
    {
        if (message != NULL)
        {
            printTime();
            printf("[Debug] \n");
            for(size_t i = 0; i < mSize; i++)
            {
                printf("%s\n", message[i]);
                //g_assert(g_printf("%s", message[i]));
            }
            printf("\n of size = %lu", mSize);
            printf("\n");
        }
    } 
}

/*
 * Function debugGHashTable
 * For hash table debugging
 */
void debugGHashTable(GHashTable* theHashTable)
{
    if (deBug)
    {
        printTime();
        printf("[Debug] HashTable list \n");
        GHashTableIter elementIterator;
        g_hash_table_iter_init(&elementIterator, theHashTable);
        gpointer hashKey, hashValue;  //gpointer used because expecting void**
        while(g_hash_table_iter_next(&elementIterator, &hashKey, &hashValue))
        {
            printf("key=%s and value=%s\n", (gchar*) hashKey, (gchar*) hashValue);
        }
        printTime();
        printf("[Debug] End of HashTable list\n");
    }
}
/*
    Debugging done
*/