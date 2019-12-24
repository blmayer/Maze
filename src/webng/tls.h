#ifndef TLS_H
#define TLS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* A structure to hold SSL information needed to exchange messages */
struct tlsSession {
	char ver[2];
	unsigned char type;
	unsigned char cli_random[32];
	unsigned char ser_random[32];
	unsigned char public[32];
	unsigned char id_len;
	unsigned char id[32];
	unsigned short cypher;
	char *proto;
};

/* The supported verions is just 1.3 hardcoded */
const char SUPPORTED_VERSIONS_EXT[6];

/* Parses the ssl handshake */
int do_tls_handshake(int conn, struct tlsSession *session);

/* Parses the internal tls fragment */
int parse_handshake(int conn, char *fragment, struct sslSession *ssl_conn);

/* Parse the tls client hello message */
int parse_client_hello(unsigned char *message, struct tlsSession *session);

int send_server_hello(int conn, struct tlsSession *session);

int send_server_cert(int conn, struct tlsSession *session);

int parse_extensions(unsigned char *msg, struct tlsSession *session);

short parse_server_name_ext(unsigned char **msg);

short parse_supported_groups_ext(unsigned char **msg);

short parse_ec_point_formats_ext(unsigned char **msg);

short parse_signature_algorithms_ext(unsigned char **msg);

short parse_use_srtp_ext(unsigned char **msg);

short parse_proto_negotiation_ext(unsigned char **msg);

short parse_padding_ext(unsigned char **msg);

int send_server_hello(int conn, struct sslSession *ssl_conn);

int parse_extensions(char *msg, struct sslSession *ssl_conn);

unsigned short parse_server_name_ext(char **msg);

unsigned short parse_supported_groups_ext(char **msg);

unsigned short parse_ec_point_formats_ext(char **msg);

unsigned short parse_signature_algorithms_ext(char **msg);

unsigned short parse_use_srtp_ext(char **msg);

short parse_unknown_ext(unsigned char **msg);

unsigned short parse_encrypt_then_mac_ext(char **msg);

unsigned short parse_extended_master_secret_ext(char **msg);

unsigned short parse_session_ticket_ext(char **msg);

unsigned char *write_key_share_ext(struct sslSession session);

#endif
