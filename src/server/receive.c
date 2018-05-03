/*
 * ****************************************************************************
 *
 * PROJECT:	Servrian: A simple HTTP 1.1 server.
 *
 * AUTHOR:	Brian Mayer blmayer@icloud.com
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

#include <web.h>
#include "receivefn.h"

int send_response(unsigned int cli_conn){
	
	/* Set the socket timeout */
	struct timeval timeout = {18, 0};	/* Timeout structure: 3 mins */
	setsockopt(cli_conn, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, 18);
 
	/* Initialize variables for reading the request */
	unsigned char *buffer = get_header(cli_conn);

	/* Check if user didn't send any data and disconnect it */
	if(strlen(buffer) == 0){
		puts("\tUser timed out or disconnected.");
		return 0;
	}

	printf("\tData received:\n%s\n", buffer);
	struct request req = {0};	/* Create our request structure */
	struct response res = {0};	/* And our response structure */
	
	/* Populate our struct with request */
	if(parse_request(buffer, &req) < 0){
		/* Probably request is encrypted */
		if(parse_request(decode(buffer, KEY), &req) < 0){
			/* Bad request received */
			puts("\tReceived bad request...");
			res.status = 400;
			unsigned char *ni_head = create_res_header(res);
			write(cli_conn, ni_head, strlen(ni_head));
			return 0;
		}
	}
	
	/* Populate the response struct based on the request struct */
	res.type = req.type;
	res.path = req.url;
	res.vers = req.vers;
	res.serv = VERSION;

	/* Optional parameters, doesn't know how to handle this nicely */
	if(req.auth == NULL){
		res.auth = NULL;
	} else {
		res.auth = req.auth;
	}
	if(req.key == NULL){
		res.key = NULL;
	} else {
		res.key = req.key;
	}
	if(req.conn == NULL){
		res.conn = "Keep-Alive";
	} else {
		res.conn = req.conn;
	}

	/* Print values for checking */
	puts("\tParsed:");
	printf("\tPath: %s\n", res.path);
	printf("\tStatus: %d\n", res.status);
	printf("\tVersion: %.1f\n", res.vers);
	printf("\tConnection: %s\n", res.conn);
	printf("\tContent Type: %s\n", res.ctype);
	printf("\tContent Length: %d\n", res.clen);
	printf("\tDate: %s\n", res.date);
	printf("\tAuthorization: %s\n", res.auth);
	printf("\tKey: %s\n", res.key);
	
	/* Process the response with the correct method */
	switch(strcmp(req.type, "PEZ")){
	case -8:
		puts("\tReceived HEAD");
		if(serve_head(cli_conn, res) < 0){
			perror("\tUnable to respond");
			return -1;
		}
		puts("\tResponse sent.");
		break;
	
	case -9:
		puts("\tProcessing GET request...");
		if(serve_get(cli_conn, res) < 0){
			perror("\tA problem occurred");
			return -1;
		}
		puts("\tResponse sent.");
		break;
	
	case 10:
		puts("\tProcessing POST request...");
		if(handle_post(cli_conn, res) < 0){
			perror("\tA problem occurred");
			return -1;
		}
		puts("\tPOST processed.");
		break;

	default:
		puts("Unsupported request.");
		res.status = 501;
		unsigned char *unsp = create_res_header(res);
		write(cli_conn, unsp, strlen(unsp));
		return 0;

	}

	/* Close connection depending on the case */
	if(strcmp(res.conn, "Close") != 0 || res.vers > 1){
		puts("\tReceiving again...");
		send_response(cli_conn);
	}

	puts("\tDisconnecting user...");
	
	return 0;
}

