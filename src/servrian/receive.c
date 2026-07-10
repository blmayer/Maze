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
	struct request req;  // Create our request structure
	struct response res; // And our response structure

	/* Set the socket timeout */
	// struct timeval tout = {180, 0}; // Timeout structure: 3 mins
	// setsockopt(cli_conn, SOL_SOCKET, SO_RCVTIMEO, (char *)&tout, 18);

	/* ---- Read the request and respond ------------------------------- */

receive:
	/* Prepare variables to receive data */
	bzero(&req, sizeof(struct request));
	bzero(&res, sizeof(struct response));
	char *header = malloc(517);

	/* Check if user didn't send any data and disconnect it */
	int mess_len = get_message(cli_conn, &header, 0); /* Read request */
	if (mess_len < 1) {
		puts("\tUser timed out or disconnected.");
		free(header);
		return 0;
	}

	puts("received data:");
	for (int i = 0; i < mess_len; i++) {
		putchar(header[i]);
	}
	puts("");

	/* ---- Check for an SSL/TLS handshake ----------------------------- */

	puts("trying to parse tls");
	struct tlsSession session;
	memset(&session, 0, sizeof(session));
	int is_tls = 0;
	int tls = do_tls_handshake(cli_conn, (unsigned char *)header, &session);
	switch (tls) {
	case 0:
		puts("not in a TLS session");
		break;
	case 1:
		puts("TLS ClientHello parsed, completing handshake...");
		/* Load cert and key, then complete handshake */
		if (CERT_PATH && KEY_PATH) {
			if (load_certificate(CERT_PATH, &session) < 0 ||
			    load_private_key(KEY_PATH, &session) < 0) {
				puts("Failed to load cert/key");
				free(header);
				return -1;
			}
			if (do_server_handshake(cli_conn, &session) < 0) {
				puts("TLS handshake failed");
				free(header);
				return -1;
			}
			is_tls = 1;
			/* Read the actual HTTP request over TLS */
			free(header);
			header = malloc(4096);
			mess_len = tls_read(cli_conn, &session,
					    (unsigned char *)header, 4095);
			if (mess_len <= 0) {
				puts("Failed to read TLS application data");
				free(header);
				return -1;
			}
			header[mess_len] = 0;
			puts("Decrypted HTTP request:");
			printf("%s\n", header);
		} else {
			puts("No cert/key configured, cannot complete TLS");
			free(header);
			return -1;
		}
		break;
	default:
		puts("Error during TLS negotiation");
		free(header);
		return tls;
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
	if (is_tls) {
		/* For TLS, build response in memory and send encrypted */
		/* Simple response: just build header + body */
		res.status = 200;
		res.stext = "OK";
		res.serv = "Servrian/" VERSION;
		res.date = "";
		res.conn = "Close";

		/* Find file path */
		char *fpath = req.url;
		if (fpath && strlen(fpath) == 1) fpath = "index.html";
		else if (fpath && fpath[0] == '/') fpath++;

		char fullpath[512];
		snprintf(fullpath, sizeof(fullpath), "%s%s", PATH, fpath);

		FILE *f = fopen(fullpath, "rb");
		if (!f) {
			/* Send 404 */
			const char *body404 = "<h1>404 Not Found</h1>";
			char resp[512];
			snprintf(resp, sizeof(resp),
				"HTTP/1.1 404 Not Found\r\n"
				"Server: Servrian/" VERSION "\r\n"
				"Content-Length: %d\r\n"
				"Connection: Close\r\n\r\n%s",
				(int)strlen(body404), body404);
			tls_write(cli_conn, &session,
				  (unsigned char *)resp, strlen(resp));
		} else {
			fseek(f, 0, SEEK_END);
			int fsize = ftell(f);
			rewind(f);

			char *body = malloc(fsize);
			fread(body, 1, fsize, f);
			fclose(f);

			char hdr_buf[512];
			snprintf(hdr_buf, sizeof(hdr_buf),
				"HTTP/1.1 200 OK\r\n"
				"Server: Servrian/" VERSION "\r\n"
				"Content-Length: %d\r\n"
				"Connection: Close\r\n\r\n", fsize);
			int hdr_len = strlen(hdr_buf);

			/* Send header + body together */
			char *full_resp = malloc(hdr_len + fsize);
			memcpy(full_resp, hdr_buf, hdr_len);
			memcpy(full_resp + hdr_len, body, fsize);
			tls_write(cli_conn, &session,
				  (unsigned char *)full_resp,
				  hdr_len + fsize);
			free(body);
			free(full_resp);
		}
		puts("\tTLS response sent.");
	} else {
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
	} /* end if is_tls else */

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
