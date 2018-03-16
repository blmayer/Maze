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
 *              write the request, wail for a responsen interpret it, and gene-
 *              rate the page.
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
#include "receivefn.h"

int main(void){

    /* Initiate a TCP socket */
    int socket, conn;

    /* Create the socket */
    socket = socket(AF_INET, SOCK_STREAM, 0);
    if(socket == -1){
        perror("Could not create socket");
    }
    puts("Socket created");

    /* Address structure */
    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8888);

    /* Connect to remote server */
    conn = connect(socket, (struct sockaddr *)&server, sizeof(server));

    if(conn < 0){
        perror("Connect failed");
        return -1;
    }
    puts("Connected\n");

	/* data that will be sent to the server */
	const char* data_to_send = "Gangadhar Hi Shaktimaan hai";
	send(sock, data_to_send, strlen(data_to_send), 0);

	// receive

	int n = 0;
	int len = 0, maxlen = 100;
	char buffer[maxlen];
	char* pbuffer = buffer;

	// will remain open until the server terminates the connection
	while ((n = recv(sock, pbuffer, maxlen, 0)) > 0) {
		pbuffer += n;
		maxlen -= n;
		len += n;

		buffer[len] = '\0';
		printf("received: '%s'\n", buffer);
	}

	close(socket);
    puts("End of program.");
    return 0;
}

