/*
 * ****************************************************************************
 *
 * PROJECT: Servrian: A simple HTTP 1.1 server.
 *
 * AUTHOR: 	Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Lee Mayer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * ****************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "receive.h"

/* Global variables with default values */
int PORT = 5000;
unsigned char *PATH = "webpages";

/* Opens a TCP socket at the desired port and listens to connections */
int main(int argc, char *argv[]){

	/* ---- Parsing command line argument ------------------------------ */

	/* Options are:
	 * -p or --port for specifying the port
	 * -h or --help for the help message, and 
	 * -d or --dir to specify a root directory for your webpages.
	 */

	int arg = 1;
	while(arg < argc){
		/* This means we have at least an argument */
		switch(strcmp(argv[arg], "--x")){
		case 59:
		case -16:
			/* This is the help, print help and quit */
			puts("Servrian/" VERSION ": A simple and encrypted"
			     " web server.\n\n"
			     "usage: servrian [--help] [-h] [--port port]"
			     " [-p port] [--dir path] [-d path]\n\n"
			     " -h: 	display this help message\n"
			     " --help: 	same as -h\n"
			     " -p port:	use 'port' as the listening"
			     " port, default 5000\n"
			     " --port port:	same as -p\n"
			     " -d path:	set 'path' to be the root"
			     " folder where your web content is located,"
			     " default ./webpages/\n"
			     " --dir path:	same as -d\n");
			return 0;
			
		case 67:
		case -8:
			/* This is the port argument, next argument is port */
			if(argv[arg + 1] != NULL){
				PORT = atoi(argv[arg + 1]);
				arg++;
			} else {
				/* Not enough arguments */
				puts("Not enough arguments.");
				return -1;
			}
			break;
		
		case 55:
		case -20:
			/* This is the port argument, next argument is port */
			if(argv[arg + 1] != NULL){
				PATH = argv[arg + 1];
				arg++;
			} else {
				/* Not enough arguments */
				puts("Not enough arguments.");
				return -1;
			}
		}
		arg++;
	}

	/* ---- Check if path is valid and contains files ----------------- */

	/* PATH must end with a / */
	if(strcmp(PATH + strlen(PATH) - 1, "/") != 0){
		/* Create a temporary variable and append the / */
		unsigned char temp[strlen(PATH) + 2];
		sprintf(temp, "%s/", PATH);
		PATH = strdup(temp);
	}
	printf("Using path: %s\n", PATH);

	/* Check if some files exist */
	unsigned char file_path[strlen(PATH) + 9];
	sprintf(file_path, "%s404.html", PATH); 
	if(fopen(file_path, "r") == NULL){
		printf("File %s not found.\n", file_path);
		return -1;
	}
	sprintf(file_path, "%s403.html", PATH); 
	if(fopen(file_path, "r") == NULL){
		printf("File %s not found.\n", file_path);
		return -1;
	}
	sprintf(file_path, "%s500.html", PATH); 
	if(fopen(file_path, "r") == NULL){
		printf("File %s not found.\n", file_path);
		return -1;
	}
	sprintf(file_path, "%s501.html", PATH); 
	if(fopen(file_path, "r") == NULL){
		printf("File %s not found.\n", file_path);
		return -1;
	}

	/* ---- Opening a socket ------------------------------------------- */

	/* Initiate a TCP socket */
	unsigned int server = socket(AF_INET, SOCK_STREAM, 0);
	if(server < 0){
		perror("Socket creation failed");
		return 0;
	}
	
	/* Make server reuse addresses */
	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	
	puts("Socket initiated!");
	
	/* I like this object now */
	struct sockaddr_in serv, client;
	
	/* The server attributes */
	serv.sin_family = AF_INET;
	serv.sin_port = htons(PORT);
	serv.sin_addr.s_addr = INADDR_ANY;		
	
	/* Bind the server to the address */
	if(bind(server, (struct sockaddr *) &serv, 16) < 0) {
		perror("Bind failed");
		close(server);
		return 0;
	}
	puts("Bind successfull.");
	
	/* ---- Listen to incoming connections  ---------------------------- */

	/* Now we listen */
	listen(server, 1);
	printf("Server is listening on port %d.\n", PORT);
	
	while(1){
		puts("Server is waiting for connections.");
		
		/* Get the new connection */
		unsigned int cli_len = sizeof(client), conn;
		conn = accept(server, (struct sockaddr *)&client, &cli_len);
		
		/*  We got a connection! Check if it is OK */
		if(conn < 0) {
			perror("Couldn't connect");
			continue;
		}
		printf("Connected to %s.\n", inet_ntoa(client.sin_addr));
		
		/* Fork the connection */
		pid_t conn_pid = fork();
		
		/* Manipulate those processes */
		if(conn_pid < 0){
			perror("Couldn't fork");
		}
		
		if(conn_pid == 0){ 		/* This is the child process */
			/* Close the parent connection */
			close(server);
			
			/* Process the response */
			send_response(conn);
			
			/* Close the client socket, not needed anymore */
			close(conn);
			puts("Client connection closed.");
			
			/* Exit the child process */
			waitpid(conn_pid, NULL, 0);
			
			exit(0);
		} else { 			/* This is the master process */
			/* Close the connection */
			close(conn);
		}
	}
	
	close(server);
	puts("End of program.");
	return 0;
}
