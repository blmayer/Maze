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

short send_response(int cli_conn)
{
	/* Initialize variables for reading the request */
	// struct timeval tout = {5, 0}; // Timeout structure: 3 mins
	struct request req;  // Create our request structure
	struct response res; // And our response structure

	/* Set the socket timeout */
	// setsockopt(cli_conn, SOL_SOCKET, SO_RCVTIMEO, (char *)&tout, 18);

	/* ---- Check for an SSL/TLS handshake ----------------------------- */

	struct tlsSession session;
	int ssl_info = do_tls_handshake(cli_conn, &session);
	if (ssl_info) {
		puts("In a SSL session");
		printf("Client random:\n");
		for(int i = 0; i < 32; i++) {
			printf("%02x ", session.random[i]);
		}
		puts("");
	}

	/* ---- Read the request and respond ------------------------------- */

receive:
	/* Prepare variables to receive data */
	bzero(&req, sizeof(struct request));
	bzero(&res, sizeof(struct response));
	char *header = malloc(517);

	/* Check if user didn't send any data and disconnect it */
	get_message(cli_conn, &header, 0); /* Read request */
	if (strlen(header) == 0) {
		puts("\tUser timed out or disconnected.");
		free(header);
		return 0;
	}

	/* Populate our struct with request */
	if (parse_request(header, &req) < 0) {
		/* Bad request received */
		puts("\tReceived bad request...");
		res.status = 400;
		req.type = "GET";
	}

	/* Print values for checking */
	puts("\tParsed:");
	printf("\tType: %s\n", req.type);
	printf("\tPath: %s\n", req.url);
	printf("\tVersion: %.1f\n", req.vers);
	printf("\tUser-Agent: %s\n", req.user);
	printf("\tConnection: %s\n", req.conn);
	printf("\tContent Type: %s\n", req.ctype);
	printf("\tContent Length: %d\n", req.clen);
	printf("\tAuthorization: %s\n", req.auth);

	/* Populate the response struct based on the request struct */
	res.type = req.type;
	res.path = req.url;
	res.vers = req.vers;
	res.serv = "Servrian/" VERSION;
	res.auth = req.auth;
	res.conn = req.conn;

	/* Process the response with the correct method */
	switch (strcmp(req.type, "PEZ")) {
	case -8:
		puts("\tReceived HEAD");
		if (serve_head(cli_conn, res) < 0) {
			perror("\tUnable to respond");
		}
		puts("\tResponse sent.");
		break;

	case -9:
		puts("\tProcessing GET request...");
		if (serve_get(cli_conn, res) < 0) {
			perror("\tA problem occurred");
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
		if (serve_get(cli_conn, res) < 0) {
			perror("\tA problem occurred");
		}
		puts("\tResponse sent.");
	}

	/* Close connection depending on the case */
	if (req.conn == NULL && req.vers > 1) {
		puts("\tReceiving again...");
		free(header);
		goto receive;
	} else if (req.conn != NULL && strcmp(req.conn, "Close")) {
		puts("\tReceiving again...");
		free(header);
		goto receive;
	}

	free(header);
	puts("\tDisconnecting user...");

	return 0;
}
