/*
 * ****************************************************************************
 *
 * PROJECT:	libwebng: A library to make encrypted requests over the web.
 *
 * AUTHOR:	Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Mayer
 *
 * ****************************************************************************
 */

#define _GNU_SOURCE
#include "webng.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void read_chunks(int conn, char *body)
{
	/* Here we read and update the body */
	puts("\tReceiving chunked data...");
	int chunk_size = 256; /* The size to be read */
	int body_size = 1;    /* This space is for the end 0 */
	char *chunk = malloc(chunk_size);
	int pos;

get_chunk:

	/* ---- Determine chunk size --------------------------------------- */

	pos = 0;
	while (read(conn, chunk + pos, 1) == 1) {

		/* The only thing that can break our loop is a line break */
		if (strcmp(chunk + pos, "\n") == 0) {
			break;
		}

		/* Increase pos by 1 to follow the buffer size */
		pos++;

		if (pos == chunk_size) {
			chunk_size += 256;
			chunk = realloc(chunk, chunk_size);
		}
	}
	sscanf(chunk, "%x", &pos); /* Hex of the chunk size */
	bzero(chunk, chunk_size);

	/* ---- Read chunk ------------------------------------------------- */

	if (pos > 0) {
		/* Allocate the size needed and read the chunk to body */
		body_size += pos;
		body = realloc(body, body_size);

		/* Now read the whole chunk, be sure */
		while (pos > 0) {
			pos -= read(conn, body + body_size - pos - 1, pos);
		}

		read(conn, chunk, 2); /* This will discard a \r\n */
		goto get_chunk;
	}

	free(chunk);
}

inline int get_ready_bytes(int conn)
{
	struct pollfd fd = {conn, POLLIN, 0};
	int ready_bytes;

	if (poll(&fd, 1, 5000) < 1) {
		return -1;
	}

	ioctl(conn, FIONREAD, &ready_bytes);
	return ready_bytes;
}

int get_message(int conn, char **buffer, int buff_start)
{
	int ready_bytes = get_ready_bytes(conn); // This blocks for 5 sec
	*buffer = realloc(*buffer, buff_start + ready_bytes);

	return read(conn, *buffer + buff_start, ready_bytes);
}

struct sslSession *do_ssl_handshake(int conn)
{
	/* Wait for minimum data */
	int mess_len = get_ready_bytes(conn);
	if (mess_len < 5) {
		return NULL;
	}

	struct sslSession *ssl_conn = malloc(sizeof(struct sslSession));

	/* ---- Read the Record Layer -------------------------------------- */

	/* First five bytes gives us enough info */
	unsigned char header[5];
	read(conn, header, 5);

	/* Handshake type */
	ssl_conn->proto = header[0];
	if (ssl_conn->proto > 23 || ssl_conn->proto < 20) {
		return NULL; // Not handshake!
	}

	/* Version */
	unsigned char maj_ver = header[1];
	unsigned char min_ver = header[2];

	/* Length of data fragment to read */
	unsigned short data_len = (header[3] << 8) + header[4];

	/* Some prints */
	printf("type: %u\n", ssl_conn->proto);
	printf("version: %d.%d\n", maj_ver, min_ver);
	printf("data_len: %d\n", data_len);

	/* Fragment */
	unsigned char *fragment = malloc(data_len);
	read(conn, fragment, data_len);
	for (int i = 0; i < data_len; i++) {
		printf("%02x ", fragment[i]);
	}
	puts("");

	/* ---- Parse the fragment ----------------------------------------- */

	switch (ssl_conn->proto) {
	case 22:
		puts("Parsing a TLS handshake");
		parse_tls_handshake(fragment, ssl_conn);
	}

	puts("Done handshake");
	free(fragment);

	return ssl_conn;
}

int parse_tls_handshake(unsigned char *fragment, struct sslSession *ssl_conn)
{
	/* Get handshake type */
	ssl_conn->type = *fragment++;

	/* Length of the fragment */
	unsigned int data_len = 0;
	data_len = *fragment++ << 16;
	data_len += *fragment++ << 8;
	data_len += *fragment++;
	printf("handshake type: %d, data len: %d\n", ssl_conn->type, data_len);

	switch (ssl_conn->type) {
	case 1:
		puts("Handshake is a client hello");
		parse_tls_client_hello(fragment, ssl_conn);
	}

	return 0;
}

int parse_tls_client_hello(unsigned char *msg, struct sslSession *ssl_conn)
{
	/* Version: for now only TLS 1.3 is supported */
	printf("version: %d.%d\n", msg[0], msg[1]);
	if (*msg++ != 3 || *msg++ != 3) {
		printf("Unsupported TLS version");
		return -1;
	}

	/* Random bytes */
	// 32 bytes discarted for now
	msg += 32;

	/* Session id */
	unsigned char id_len = *msg++; // byte 35 has the session id length
	printf("session id len: %d\n", id_len);
	if (id_len > 0) {
		ssl_conn->id = malloc(id_len);
		printf("session id: ");
		for (int i = 0; i < id_len; i++) {
			printf("%x", i);
			ssl_conn->id[i] = *msg++;
		}
		ssl_conn->id[id_len] = '\0';
		puts("");
	} else {
		ssl_conn->id = 0;
	}

	/* Cipher suites parsing */
	unsigned short ciphers_len = *msg++ << 8;
	ciphers_len += *msg++;
	printf("ciphers len: %d\n", ciphers_len);
	for (int i = 0; i < ciphers_len; i++) {
		printf("%02x ", *msg++);
	}

	/* Compression methods */
	unsigned short cmp_len = *msg++;
	printf("\ncompression len: %d\n", cmp_len);

	/* TLS 1.3 only has compression 0 */
	for (int i = 0; i < cmp_len; i++) {
		printf("compression %d: %d\n", i, *msg++);
	}

	/* Extensions */
	puts("Parsing extensions");
	parse_extensions(msg, ssl_conn);

	return 0;
}

int parse_extensions(unsigned char *msg, struct sslSession *sslConn)
{
	/* Length of all extensions */
	unsigned short exts_len = *msg++ << 8;
	exts_len += *msg++;

	/* Loop in all extensions */
	while (exts_len) {
		sleep(1);
		printf("extensions len: %d\n", exts_len);

		/* Extension id or type */
		printf("extension: %02x ", *msg);
		unsigned short ext_type = *msg++ << 8;
		printf("%02x\n", *msg);
		ext_type += *msg++;

		/* Continue parsing with the correct method */
		switch (ext_type) {
		case 0:
			puts("Reading SNI");
			exts_len -= parse_server_name_ext(&msg);
			break;
		case 14:
			puts("Reading SRTP extension");
			exts_len -= parse_use_srtp_ext(&msg);
			break;
		case 11:
			puts("Reading EC point formats");
			exts_len -= parse_ec_point_formats_ext(&msg);
			break;
		default:
			printf("Unknown extension: %d\n", ext_type);
			unsigned short ext_len = *msg++ << 8;
			ext_len += *msg++;
			printf("this ext len: %d\n", ext_len);
			exts_len -= ext_len;
		}

		/* Jump to next extension */
		exts_len -= 2;
	}

	return 0;
}

unsigned short parse_server_name_ext(unsigned char **msg)
{
	/* Server name extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len);

	/* This is a list */
	unsigned short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("Server names list len: %d\n", list_len);

	/* Loop in the list of names */
	while (list_len) {
		/* Types: 0: host name */
		unsigned char name_type = *(*msg)++;
		printf("name type: %d\n", name_type);

		/* Case hostname */
		unsigned short name_len;
		if (name_type == 0) {
			/* String length */
			name_len = *(*msg)++ << 8;
			name_len += *(*msg)++;
			if (name_len == 0) {
				puts("Invalid name length");
				break;
			}

			printf("Host name len: %d\n", name_len);
			list_len -= name_len;
			while (name_len-- > 0) {
				printf("%c", *(*msg)++);
			}

			puts("");
		}

		/* Go to next item in list */
		list_len -= 3;
	}

	puts("parsed name ext");
	return ext_len;
}

unsigned short parse_use_srtp_ext(unsigned char **msg)
{
	/* SRTP Protection Profile */
	unsigned short profile = **msg++ << 8;
	profile += **msg++;
	printf("profiles: %d\n", profile);

	/* Read profiles */
	while (profile--) {
		printf("Profile value: %02x ", **msg++);
		printf("%02x\n", **msg++);
	}

	/* Length of SRTP MKI */
	unsigned char mki_len = **msg++;
	printf("mki_len: %d\n", mki_len);

	/* Read MKI */
	while (mki_len--) {
		printf("%c", **msg++);
	}

	return 2 + profile + mki_len;
}

unsigned short parse_ec_point_formats_ext(unsigned char **msg)
{
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("points format bytes: %d\n", ext_len);
	for (int i = 0; i < ext_len; i++) {
		printf("%02x ", *(*msg)++);
	}

	return ext_len;
}

short parse_URL(char *url, struct url *addr)
{
	/* At first proto looks at the start of the URL */
	addr->proto = url;

	/* Try to match cases http://domain... and //domain... in URL */
	addr->domain = strstr(url, "://");
	if (addr->domain != NULL) {
		strcpy(addr->domain, "\0");
		addr->domain = addr->domain + 3;
	} else {
		/* URL starts with domain: www.domain... */
		addr->domain = url;
		addr->proto = NULL;
	}

	/* Try to find the port */
	addr->port = strstr(addr->domain, ":");
	if (addr->port == NULL) {
		addr->port = strstr(addr->domain, "/");
	} else {
		/* Writing \0 to delimit URL parts */
		strcpy(addr->port, "\0");
		addr->port++;
	}

	/* Search for a / */
	if (addr->port != NULL) {
		addr->path = strstr(addr->port, "/");
		if (addr->path != NULL) {
			strcpy(addr->path, "\0");
			addr->path++;

			/* The last is ? */
			addr->pars = strstr(addr->path, "?");
		} else {
			addr->pars = strstr(addr->port, "?");
		}
	}

	/* Delimit path */
	if (addr->pars != NULL) {
		strcpy(addr->pars, "\0");
		addr->pars++;
	}

	return 0;
}

short parse_request(char *message, struct request *req)
{
	/* Get first line parameters */
	req->type = strtok(message, " "); /* First token is the method */
	if (req->type == NULL) {
		puts("\tCould not parse the method.");
		return -1;
	}

	req->url = strtok(NULL, " "); /* Then the url or path */
	strtok(NULL, "/");	    /* Advance to the version no */

	/* Due to atof we need to test for a NULL pointer */
	char *ver = strtok(NULL, "\r\n");
	if (ver != NULL) {
		req->vers = atof(ver); /* Lastly the HTTP version */
	} else {
		puts("\tCould not parse header's version.");
		return -1;
	}

	/* Put pointer in next line */
	char *temp = strtok(NULL, "\r\n");

	while (temp != NULL) {
		/* Keep advancing in string getting some parameters */
		if (strncmp(temp, "Host: ", 6) == 0) {
			req->host = temp + 6;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "User-Agent: ", 12) == 0) {
			req->user = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Authorization: ", 15) == 0) {
			req->auth = temp + 15;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Content-Length: ", 16) == 0) {
			req->clen = atoi(temp + 16);
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Content-Type: ", 14) == 0) {
			req->ctype = temp + 14;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Content-Encoding: ", 18) == 0) {
			req->cenc = temp + 18;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Connection: ", 12) == 0) {
			req->conn = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		temp = strtok(NULL, "\r\n");
	}

	return 0;
}

short parse_response(char *message, struct response *res)
{
	/* ---- Get first line parameters
	 * ---------------------------------- */

	/* Due to atof we need to test for a NULL pointer */
	char *ver = strtok(message, " ");
	if (ver != NULL) {
		/* The HTTP version */
		res->vers = atof(ver + 5);
	} else {
		puts("\tCould not parse header's version.");
		return -1;
	}

	/* Advance to the status */
	char *stat = strtok(NULL, " ");
	if (stat != NULL) {
		/* Lastly the HTTP status */
		res->status = atoi(stat);
	} else {
		puts("\tCould not parse header's status.");
		return -1;
	}

	/* Put pointer in next line */
	char *temp = strtok(NULL, "\r\n");

	while (temp != NULL) {
		/* Keep advancing in string getting some parameters */
		if (strncmp(temp, "Server: ", 8) == 0) {
			res->serv = temp + 8;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Date: ", 6) == 0) {
			res->date = temp + 6;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Authorization: ", 15) == 0) {
			res->auth = temp + 15;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Content-Length: ", 16) == 0) {
			res->clen = atoi(temp + 16);
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Content-Type: ", 14) == 0) {
			res->ctype = temp + 14;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Content-Encoding: ", 18) == 0) {
			res->cenc = temp + 18;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Connection: ", 12) == 0) {
			res->conn = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if (strncmp(temp, "Transfer-Encoding: ", 19) == 0) {
			res->ttype = temp + 19;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		temp = strtok(NULL, "\r\n");
	}

	return 0;
}

short req_header_len(struct request req)
{
	/* URL request line, includes version, spaces and \r\n */
	short header_size = strlen(req.type) + strlen(req.url) + 12;

	header_size += 8 + strlen(req.host);  /* Host: \r\n */
	header_size += 14 + strlen(req.user); /* User-Agent: \r\n */
	header_size += 14 + strlen(req.conn); /* Connection: \r\n */
	header_size += 10 + strlen(req.cenc); /* Accept: \r\n */

	/* And optional lines */
	if (req.auth != NULL) {
		header_size += 17 + strlen(req.auth);
	}

	/* File length line, if we want */
	if (req.clen > 0) {
		/* Count the number of digits */
		int number = req.clen;
		short digits = 0;
		while (number != 0) {
			number /= 10;
			digits++;
		}
		header_size += digits + 18;	    /* Number of digits */
		header_size += 14 + strlen(req.ctype); /* Content Encoding */
	}
	return header_size + 1; /* Terminating zero */
}

short create_req_header(struct request req, char *dest)
{
	/* Copy all parameters to it */
	sprintf(dest,
		"%s %s HTTP/%.1f\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Connection: %s\r\n"
		"Accept: %s\r\n",
		req.type, req.url, req.vers, req.host, req.user, req.conn,
		req.cenc);

	/* Optional lines */
	if (req.auth != NULL) {
		sprintf(dest + strlen(dest), "Authorization: %s\r\n", req.auth);
	}
	if (req.clen > 0) {
		sprintf(dest + strlen(dest),
			"Content-Type: %s\r\n"
			"Content-Length: %d\r\n",
			req.ctype, req.clen);
	}

	return 0;
}

short res_header_len(struct response res)
{
	/* URL request line, includes version, spaces and \r\n */
	short header_size = 14; /* Size of HTTP/1.1 + xxx + \r\n */

	header_size += 1 + strlen(res.stext); /* Status text part */
	header_size += 10 + strlen(res.serv); /* Server information line */
	header_size += 8 + strlen(res.date);  /* Now the server time line */
	header_size += 14 + strlen(res.conn); /* Connection: \r\n */

	/* File length line, if we want */
	if (res.clen > 0) {
		/* Count the number of digits */
		int number = res.clen;
		short digits = 0;
		while (number != 0) {
			number /= 10;
			digits++;
		}
		header_size += digits + 18;	    /* Number of digits */
		header_size += 16 + strlen(res.ctype); /* Content Encoding */
	}

	return header_size + 1; /* Terminating zero */
}

short create_res_header(struct response res, char *dest)
{
	/* Copy all parameters to it */
	sprintf(dest,
		"HTTP/%.1f %hd %s\r\n"
		"Server: %s\r\nDate: %s\r\nConnection: %s\r\n",
		res.vers, res.status, res.stext, res.serv, res.date, res.conn);

	/* Optional lines */
	if (res.clen > 0) {
		sprintf(dest + strlen(dest),
			"Content-Type: %s\r\nContent-Length: %d\r\n", res.ctype,
			res.clen);
	}

	return 0;
}

// void encode(char *message, char *key)
// {
// 	/* Get length of received message and key */
// 	int n = strlen(message);
// 	int i = 0;

// 	/* Loop changing characters */
// 	while (i < n) {
// 		message[i] = (message[i] ^ key[i % 512]) + 33;
// 		i++;
// 	}

// 	message[n] = 0; /* Add terminating zero */
// }

// void decode(char *cipher, char *key)
// {
// 	/* Get length of received message and key */
// 	int n = strlen(cipher);
// 	int i = 0;

// 	/* Loop changing characters */
// 	while (i < n) {
// 		cipher[i] = (cipher[i] - 33) ^ key[i % 512];
// 		i++;
// 	}

// 	cipher[n] = 0; /* Add terminating zero */
// }
