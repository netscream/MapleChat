#include "printing.h" //include header file

/* 
 * Function printToOutput
 * for printing to output with a timestamp
 */
void printToOutput(char* message, int length)
{
    printTime();
    //fprintf(stdout, "[+] %s\n", message);
    fprintf(stdout, "[+] ");
    for (int i = 0; i < length; i++)
    {
        fprintf(stdout, "%d ", message[i]);
    }
    fprintf(stdout, "\n");
}

/* 
 * Function printToOutputRequest
 * for printing to output from requests with a timestamp
 */
void printToOutputSendHeader(char* header, int oneIfFromClient, struct sockaddr_in clientAddr)
{
    if (oneIfFromClient == 1)
    {
        printf("Header from client %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
    }
    else
    {
        printf("Header sent to client %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
    }
    printf("-------------------------\n");
	printf("%s\n", header);
    printf("-------------------------\n\n");
}

/* 
 * Function printToOutput
 * for printing to output from errors with a timestamp
 */
void printToOutputError(char* message, struct sockaddr_in clientAddr)
{
    printTime();
    fprintf(stdout, "[+] Error message: \"%s\" sent to %s:%d\n", message, inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
}

/*
 * Function printBanner
 * only for printing banner to stdout
 */
void printBanner()
{
    printf("------------------------------------------------\n");
    printf("|      OpenSSL chat server for tsam course     |\n");
    printf("|   Authors:                                   |\n");
    printf("|   Hlynur Hansen           <hlynur14@ru.is>   |\n");
    printf("------------------------------------------------\n");
}

/*
 * Function getHeaderTime
 * For time configurations header and logfile
 * mode:
 *     1 = HEADER
 *     2 = logfile
 */
void getHeaderTime(char* buffer, int mode)
{
    time_t timer = time(NULL); 
    struct tm *loctime;
    loctime = localtime(&timer);
    if (mode == 1)
    {
        strftime(buffer, 40, "%a, %d %b %G %T, %Z", loctime); //day,name, daynumber, monthname, year(4), time(24hr), timezone
    }
    else
    if (mode == 2)
    {
        strftime(buffer, 21, "%F %T", loctime); //hh:mm:ss
    }
}