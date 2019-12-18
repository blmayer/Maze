#include "tls.h"

/*
 * TODO: Use an int to keep track of *msg
 */
int parse_extensions(char *msg, struct sslSession *ssl_conn)
{
	/* Length of all extensions */
	unsigned short exts_len = *msg++ << 8;
	exts_len += *msg++;

	/* Loop in all extensions */
	while (exts_len) {
		sleep(1);
		printf("extensions len: %d\n", exts_len);

		/* Extension id or type */
		unsigned short ext_type = *msg++ << 8;
		ext_type += *msg++;
        exts_len -= 2;
		printf("extension: %d\n", ext_type);

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
        case 22:
            puts("Reading Encrypt-then-MAC extension");
            exts_len -= parse_encrypt_then_mac_ext(&msg);
			break;
        case 23:
            puts("Reading Extended Master Secret Extension");
            exts_len -= parse_extended_master_secret_ext(&msg);
            break;
        case 35:
            puts("Reading SessionTicket TLS Extension");
			exts_len -= parse_session_ticket_ext(&msg);
			break;
		default:
			printf("Unknown extension: %d\n", ext_type);
			unsigned short ext_len = *msg++ << 8;
			ext_len += *msg++;
			printf("this ext len: %d\n", ext_len);
			exts_len -= ext_len;
		}
	}

	return 0;
}

unsigned short parse_server_name_ext(char **msg)
{
	/* Server name extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len +2);

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

unsigned short parse_supported_groups_ext(char **msg)
{
	/* Supported groups extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

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

unsigned short parse_ec_point_formats_ext(char **msg)
{
	/* EC point formats extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	// Just print the formats
	for (int i = 0; i < ext_len; i += 2) {
		printf("%02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	puts("parsed EC point formats ext");
	return ext_len + 2;
}

unsigned short parse_signature_algorithms_ext(char **msg)
{
	/* Signature algorithms extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

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

unsigned short parse_use_srtp_ext(char **msg)
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

unsigned short parse_proto_negotiation_ext(char **msg)
{
	/* App-Layer protocol negotiation length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

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
	return ext_len + 2;
}

unsigned short parse_encrypt_then_mac_ext(char **msg)
{
    /* Encrypt-on-MAC extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

    /* This must be zero */
    return ext_len + 2;
}

unsigned short parse_extended_master_secret_ext(char **msg)
{
    /* Extended master secret extension length */
    unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

    /* This must be zero */
    return ext_len + 2;
}

unsigned short parse_session_ticket_ext(char **msg)
{
    /* Ticket extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

    /* We don't resume session tickets, skip the bytes */
    for (int i = 0; i < ext_len; i++) {
		printf("%02x ", **msg++);
	}
    puts("");

    puts("Parsed session ticket");
    return ext_len + 2;
}