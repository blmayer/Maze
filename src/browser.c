/*
 * ****************************************************************************
 *
 * PROJECT:     Maze: A simple HTTP 1.1 web browser.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018    Brian Lee Mayer
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
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "headers.h"
#include "getfn.h"

int main(int argc, char *argv[]){

	/* Get URL from command line */
	char *url;
	if(argc < 2){
		puts("Please enter a valid URL.");
	} else {
		url = argv[1];
	}
	
	/* Lookup host name */
	struct hostent *address = gethostbyname(url);
    if(address == NULL){
        /* Get the host info */
        perror("Unable to resolve host");
        return -1;
    }
 
	/* Initialize IP addresses list */
    struct in_addr **addr_list;
    addr_list = (struct in_addr **) address -> h_addr_list;
    
	/* Return the first IP found */
	int i = 0;
	struct in_addr *ip;
    while(addr_list[i] != NULL){
        ip = addr_list[i];
		if(ip != NULL){
			break;
		}
		i++;
    }
	
	if(addr_list[i] == NULL){
		puts("Could not find an IP.");
		return -1;
	}
	
	/* IP found, now we connect */
	struct addrinfo client = {0};
	client.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    client.ai_socktype = SOCK_STREAM; /* Datagram socket */
    client.ai_flags = 0;
    client.ai_protocol = 0;           /* Any protocol */
	client.ai_addr = (struct sockaddr *)ip;
	
	/* Open a socket */
	int tcp_server = socket(AF_INET, SOCK_STREAM, 0);
	if(tcp_server < 0){
		perror("Socket creation failed");
		return 0;
	}

	/* And try to connect */
	int conn;
	connect(conn, (struct sockaddr *)ip, sizeof(ip));
	if(conn == -1){
		perror("Could not connect");
		return -2;
	}
	puts("Connection successful!");
	
	/* Create a request structure */
	struct request req = {0};
	req.type = "GET";
	req.url = url;
	req.vers = "1.1";
	req.host = url;
	req.conn = "Keep-Alive";
	
	/* Send an encrypted GET request */
	send_get(conn, req, 0);
	
	/* Initialize variables for reading the request */
    puts("\tReady to receive.");
    int pos = 0, buff_size = 1024;
    unsigned char *buffer = calloc(buff_size, 1);
    unsigned char *dec_buffer = calloc(buff_size, 1);

    /* This is a loop that will read the data coming from our connection */
    while(read(conn, buffer + pos, 1) == 1){
        
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
	
	puts(buffer);
	puts(dec_buffer);
	
	free(buffer);
	free(dec_buffer);
	
	close(conn);
	close(tcp_server);
	
	return 0;
}
