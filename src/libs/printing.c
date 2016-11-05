#include "printing.h" //include header file

/* 
 * Function printToOutput
 * for printing to output with a timestamp
 */
void print_to_output(char* message, int length)
{
    print_time();
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
void print_to_output_send_header(char* header, int one_if_from_client, struct sockaddr_in client_addr)
{
    if (one_if_from_client == 1)
    {
        printf("Header from client %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    }
    else
    {
        printf("Header sent to client %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    }
    printf("-------------------------\n");
	printf("%s\n", header);
    printf("-------------------------\n\n");
}

/* 
 * Function printToOutput
 * for printing to output from errors with a timestamp
 */
void print_to_output_error(char* message, struct sockaddr_in client_addr)
{
    print_time();
    fprintf(stdout, "[+] Error message: \"%s\" sent to %s:%d\n", message, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
}

/*
 * Function printBanner
 * only for printing banner to stdout
 */
void print_banner()
{
    printf("------------------------------------------------\n");
    printf("|      Mable chat server for tsam course       |\n");
    printf("|   Authors:                                   |\n");
    printf("|   Arnar Páll Jóhannsson   <arnarpj15@ru.is>  |\n");
    printf("|   Hlynur Óskar Guðmundsson<hlynur15@ru.is>   |\n");
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
void get_header_time(char* buffer, int mode)
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

/*
 * Function logToConsole
 * For client connection logging
 */
void log_to_console(struct sockaddr_in client_addr)
{
    debug_s("Logging to file");
    int len = 20;
    char cl_bugg[len];
    char buffer[512];
    memset(&buffer, 0, 512);
    char the_time[21];
    char port_id[2];
    sprintf(port_id,"%d", ntohs(client_addr.sin_port));
    get_header_time(the_time, 2);
    debug_s("Creating buffer");
    strcat(buffer, the_time); //time ISO-8601 compliant
    strcat(buffer, " : ");
    strcat(buffer, inet_ntop(AF_INET, &(client_addr.sin_addr), cl_bugg, len)); //ip address
    strcat(buffer, ":");
    strcat(buffer, port_id); //port
    strcat(buffer, " ");
    strcat(buffer, " : ");
    strcat(buffer, "connected");
    strcat(buffer, "\n");
    printf("%s", buffer);
    debug_s("Returning from logtofile");
    return;
}