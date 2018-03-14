/*
 * ****************************************************************************
 *
 * PROJECT:     Servrian
 *
 * TITLE:       Simple HTTP 1.1 server.
 *
 * FUNCTION:    This is the main file, here we manage to open TCP connections
 *              at port 5000 and wait for users to connect. Then each connec -
 *              tion is processed by a different thread, created by a fork
 *              command, that will read the request, interpret it, and generate
 *              a response.
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

int main(void) {

    /* Initiate a TCP socket */
    int tcp_server = socket(AF_INET, SOCK_STREAM, 0);
    if(tcp_server < 0) {
        perror("Socket creation failed");
        return 0;
    }
    
    /* To be able to reuse the port and the address */
    int en = 1;                              /* This is ridiculous! */
    
    /* Make server reuse addresses, ports and set timeout */
    setsockopt(tcp_server, SOL_SOCKET, SO_REUSEADDR, &en, 7);
    
    puts("Socket initiated!");
    
    /* The fucking object that only holds configs */
    struct sockaddr_in server, client;
    
    /* The server attributes */
    server.sin_family = AF_INET;
    server.sin_port = htons(5000);
    server.sin_addr.s_addr = INADDR_ANY;        
    
    /* Bind the server to the address */
    if(bind(tcp_server, (struct sockaddr *) &server, 16) < 0) {
        perror("Bind failed");
        close(tcp_server);
        return 0;
    }
    puts("Bind successfull.");
    
    /* Now we listen */
    listen(tcp_server, 1);
    puts("Server is receiving on port 5000.");
    
    while(1){
        
        /* Get the new connection */
        int cli_len = sizeof(client), cli_conn;
        cli_conn = accept(tcp_server, (struct sockaddr *)&client, &cli_len);
        
        /*  We got a connection! Check if it is OK */
        if(cli_conn < 0) {
            perror("Couldn't connect");
            continue;
        }
        printf("Connected to %s, forking...\n", inet_ntoa(client.sin_addr));
        
        /* Fork the connection */
        pid_t conn_pid = fork();
        
        /* Manipulate those processes */
        if(conn_pid < 0) {
            perror("Couldn't fork");
        }
        
        if(conn_pid == 0) {
            /* This is the child process */
            
            /* Close the parent connection */
            close(tcp_server);
            
            /* Process the response */
            send_response(cli_conn);
            
            /* Close the client socket, not needed anymore */
            close(cli_conn);
            puts("Client connection closed.");
            
            /* Exit the child process */
            waitpid(conn_pid, NULL, 0);
            
            exit(0);
        } else {
            /* This is the master process */
            
            /* Close the connection */
            close(cli_conn);
        }
    }
    
    close(tcp_server);
    puts("End of program.");
    return 0;
}

