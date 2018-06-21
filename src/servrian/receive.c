/*
 * ****************************************************************************
 *
 * PROJECT:	Servrian: A simple HTTP 1.1 server.
 *
 * AUTHOR:	Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Mayer
 *
 * ****************************************************************************
 */

#include "receive.h"

short send_response(short cli_conn){
	
	/* Set the socket timeout */
	struct timeval timeout = {180, 0};	/* Timeout structure: 3 mins */
	setsockopt(cli_conn, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, 18);
 
	/* Initialize variables for reading the request */
	char *header = malloc(32);	/* Very close to the minimum of 29 */
	get_header(cli_conn, header);

	/* Check if user didn't send any data and disconnect it */
	if(strlen(header) == 0) {
		puts("\tUser timed out or disconnected.");
		return 0;
	}

	struct request req = {0};	/* Create our request structure */
	struct response res = {0};	/* And our response structure */
	
	/* Populate our struct with request */
	if(parse_request(header, &req) < 0) {
		/* Probably request is encrypted */
		puts("\tTrying to parse an encrypted request...");
		if(parse_request(decode(header, KEY), &req) < 0) {
			/* Bad request received */
			puts("\tReceived bad request...");
			res.status = 400;
		}
	}
	
	/* Print values for checking */
	puts("\tParsed:");
	printf("\tPath: %s\n", req.url);
	printf("\tVersion: %.1f\n", req.vers);
	printf("\tUser-Agent: %s\n", req.user);
	printf("\tConnection: %s\n", req.conn);
	printf("\tContent Type: %s\n", req.ctype);
	printf("\tContent Length: %d\n", req.clen);
	printf("\tAuthorization: %s\n", req.auth);
	printf("\tKey: %s\n", req.key);
	
	/* Populate the response struct based on the request struct */
	res.type = req.type;
	res.path = req.url;
	res.vers = req.vers;
	res.serv = "Servrian/" VERSION;

	/* Optional parameters, doesn't know how to handle this nicely */
	if(req.auth == NULL) {
		res.auth = NULL;
	} else {
		res.auth = req.auth;
	}
	if(req.key == NULL) {
		res.key = NULL;
	} else {
		res.key = req.key;
	}
	if(req.conn == NULL) {
		res.conn = "Keep-Alive";
	} else {
		res.conn = req.conn;
	}

	/* Process the response with the correct method */
	switch(strcmp(req.type, "PEZ")) {
	case -8:
		puts("\tReceived HEAD");
		if(serve_head(cli_conn, res) < 0) {
			perror("\tUnable to respond");
			return -1;
		}
		puts("\tResponse sent.");
		break;
	
	case -9:
		puts("\tProcessing GET request...");
		if(serve_get(cli_conn, res) < 0) {
			perror("\tA problem occurred");
			return -1;
		}
		puts("\tResponse sent.");
		break;
	
	// case 10:
	// 	puts("\tProcessing POST request...");
	// 	if(handle_post(cli_conn, res) < 0) {
	// 		perror("\tA problem occurred");
	// 		return -1;
	// 	}
	// 	puts("\tPOST processed.");
	// 	break;

	default:
		puts("Unsupported request.");
		res.status = 501;
		if(serve_get(cli_conn, res) < 0) {
			perror("\tA problem occurred");
			return -1;
		}
		puts("\tResponse sent.");
	}

	/* Close connection depending on the case */
	if(strcmp(res.conn, "Close") != 0 || res.vers > 1) {
		puts("\tReceiving again...");
		send_response(cli_conn);
	}

	free(header);
	puts("\tDisconnecting user...");
	
	return 0;
}

