/*
 * ****************************************************************************
 *
 * PROJECT:	Maze: A simple HTTP 1.1 web browser.
 *
 * AUTHOR: 	Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Lee Mayer
 *
 * ****************************************************************************
 */

#include "get.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <webng.h>

int main(int argc, char *argv[])
{
	/* Get URL and port from command line */
	if (argc != 2) {
		puts("Please input exactly one parameter");
	}

	/* ---- Parse the url entered to get host, path and parameters ----- */

	struct url url = {0};
	parse_URL(argv[1], &url);

	/* Lookup host name */
	struct addrinfo hints = {0};
	struct addrinfo *host;

	hints.ai_family = AF_INET;       /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* TCP socket */
	hints.ai_flags = 0;		 /* For wildcard IP address */
	hints.ai_protocol = 0;		 /* Any protocol */

	int lookup = getaddrinfo(url.domain, url.port, &hints, &host);
	if (lookup != 0) {
		/* Get the host info */
		puts("Unable to resolve host.");
		return -1;
	}

	/* Open a socket */
	int server = socket(AF_INET, SOCK_STREAM, 0);
	if (server < 0) {
		perror("Socket creation failed");
		return 0;
	}

	/* Loop on the returned result checking for an address */
	while (connect(server, host->ai_addr, host->ai_addrlen) == -1) {
		host = host->ai_next;
	}

	if (host == NULL) {
		puts("Could not connect.");
		return -1;
	}
	puts("Connection successful!");

	/* Set the socket timeout */
	struct timeval timeout = {10, 0}; /* Timeout structure: 10 seconds */
	setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, 18);

	/* Create a request structure */
	struct request req = {0};
	req.type = "GET";
	req.url = url.path;
	req.vers = 1.1;
	req.conn = "Keep-Alive";

	if (host->ai_canonname == NULL) {
		req.host = url.domain;
	} else {
		req.host = host->ai_canonname;
	}

	/* Send a not yet encrypted GET request */
	send_get(server, req);

	/* ---- Read response's body --------------------------------------- */

	/* Populate the response struct */
	char *response = malloc(128);
	get_message(server, &response, 0);

	printf("received\n'%s'\n", response);
	struct response res = {0};
	if (parse_response(response, &res) < 0) {
		puts("Bad response.");
		return 0;
	}

	/* Print values for checking */
	puts("\tParsed:");
	printf("\tVersion: %.1f\n", res.vers);
	printf("\tStatus: %d\n", res.status);
	printf("\tServer: %s\n", res.serv);
	printf("\tConnection: %s\n", res.conn);
	printf("\tContent Type: %s\n", res.ctype);
	printf("\tContent Length: %d\n", res.clen);
	printf("\tDate: %s\n", res.date);
	printf("\tAuthorization: %s\n", res.auth);

	/* ---- Receiving the body ----------------------------------------- */

	res.body = malloc(1);

	/* The transfer may be normal */
	if (res.clen > 0) {
		/* Reallocate space for the body */
		res.body = realloc(res.body, res.clen + 1);

		/* Read the content from the socket */
		read(server, res.body, res.clen);
		res.body[res.clen] = 0;
	}

	/* Or may be chunked */
	if (res.ttype != NULL && strcmp(res.ttype, "chunked") == 0) {
		/* Here we read and update the body */
		char *temp = malloc(1);
		read_chunks(server, temp);
		res.body = temp;
	}

	printf("Body:\n%s\n", res.body);
	close(server);
	free(res.body);
	free(response);

	return 0;
}
