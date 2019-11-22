#include "tls.h"

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
	if (header[0] > 23 || header[0] < 20) {
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

	switch (header[0]) {
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
		printf("session id: ");
		for (int i = 0; i < id_len; i++) {
			printf("%x", i);
			ssl_conn->id[i] = *msg++;
		}
		ssl_conn->id[id_len] = '\0';
		puts("");
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
	puts("Done parsing client hello");

	return 0;
}

/*
 * TODO: Use an int to keep track of *msg
 */
int parse_extensions(unsigned char *msg, struct sslSession *sslConn)
{
	/* Length of all extensions */
	unsigned short exts_len = *msg++ << 8;
	exts_len += *msg++ - 2;

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
		case 10:
			puts("Reading supported groups");
			exts_len -= parse_supported_groups_ext(&msg);
			break;
		case 11:
			puts("Reading EC point formats");
			exts_len -= parse_ec_point_formats_ext(&msg);
			break;
		case 13:
			puts("Reading signature algorithms");
			exts_len -= parse_signature_algorithms_ext(&msg);
			break;
		case 14:
			puts("Reading SRTP extension");
			exts_len -= parse_use_srtp_ext(&msg);
			break;
		case 16:
			puts("Reading protocol negotiation extension");
			exts_len -= parse_proto_negotiation_ext(&msg);
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
	return ext_len + 2;
}

unsigned short parse_supported_groups_ext(unsigned char **msg)
{
	/* Supported groups extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len);

	/* This is a list */
	unsigned short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("Supported groups list len: %d\n", list_len);

	/* Loop in the list of groups */
	for (int i = 0; i < list_len; i += 2) {
		printf("%02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	puts("parsed supported groups ext");
	return ext_len + 2;
}

unsigned short parse_ec_point_formats_ext(unsigned char **msg)
{
	/* EC point formats extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len);

	// Just print the formats
	for (int i = 0; i < ext_len; i += 2) {
		printf("%02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	puts("parsed EC point formats ext");
	return ext_len + 2;
}

unsigned short parse_signature_algorithms_ext(unsigned char **msg)
{
	/* Signature algorithms extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len);

	/* This is a list */
	unsigned short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("algorithms list len: %d\n", list_len);

	/* Loop in the list of groups */
	for (int i = 0; i < list_len; i += 2) {
		printf("%02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	puts("parsed signature algorithms ext");
	return ext_len + 2;
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

unsigned short parse_proto_negotiation_ext(unsigned char **msg)
{
	/* App-Layer protocol negotiation length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len);

	/* This is a list */
	unsigned short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("protocol names list len: %d\n", list_len);

	/* Loop in the list of names */
	while (list_len) {
		/* String length */
		unsigned char name_len = *(*msg)++;
		if (name_len == 0) {
			puts("Invalid name length");
			break;
		}

		printf("protocol name len: %d\n", name_len);
		list_len -= name_len;
		while (name_len--) {
			printf("%c", *(*msg)++);
		}
		puts("");

		/* Go to next item in list */
		list_len--;
	}

	puts("parsed protocol negotiation ext");
	return ext_len;
}
