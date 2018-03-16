/*
 * ****************************************************************************
 *
 * PROJECT:     Maze
 *
 * TITLE:       Simple HTTP 1.1 web browser.
 *
 * FUNCTION:    This is the main file, here we manage to open TCP connections
 *              in order to connect to an URL. Then each connection is proces -
 *              sed by a different thread, created by a fork command, that will
 *              write the request, wail for a response and interpret it, and 
 *              generate the page.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:       
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ****************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "connect.h"

int main(void){

    /* Initiate a TCP socket */
    int conn_socket;

    /* Create the socket */
    conn_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(conn_socket == -1){
        perror("Could not create socket");
    }
    puts("Socket created");

    /* Address structure */
    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8888);

    /* Connect to remote server */
    if(connect(conn_socket, (struct sockaddr *)&server, sizeof(server)) < 0){
        perror("Connect failed");
        return -1;
    }
    puts("Connected\n");

	/* Send a GET request to the server */
	unsigned char* request;
    
	send(conn_socket, data_to_send, strlen(data_to_send), 0);

    /* Initialize variables for reading the request */
    puts("\tReady to receive.");
    int pos = 0, buff_size = 1024;
    unsigned char *buffer = calloc(buff_size, 1);
    unsigned char *dec_buffer = calloc(buff_size, 1);

    /* This is a loop that will read the data comming from our connection */
    while(read(conn_socket, buffer + pos, 1) == 1){
        
        /* Decode while we read */
        dec_buffer[pos] = (buffer[pos] - 1) ^ KEY[pos % 512];
        
        /* Increase pos by 1 to follow the buffer size */
        pos++;
        
        /* The only thing that can break our loop is a blank line */
        if(strcmp(buffer + pos - 4, "\r\n\r\n") == 0){ 
            break;
        }
        
        if(pos == buff_size){
            puts("\t\tBuffer grew.");
            buff_size += 512;
            buffer = realloc(buffer, buff_size);
            dec_buffer = realloc(dec_buffer, buff_size);
        }
    }

	close(conn_socket);
    puts("End of program.");
    return 0;
}

