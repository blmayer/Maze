#ifndef TLS_H
#define TLS_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* A structure to hold SSL information needed to exchange messages */
struct tlsSession {
	char ver[2];
	unsigned char type;
	unsigned char cipher[2];
	unsigned char cli_random[32];
	unsigned char ser_random[32];
	unsigned char cli_public[32];
	unsigned char ser_public[32];
	unsigned char ser_private[32];
	unsigned char id_len;
	unsigned char id[32];
	char *proto;
	char renegotiation_set;
	char master_secret_set;
};

/* Parses the ssl handshake */
int do_tls_handshake(int conn, unsigned char *msg, struct tlsSession *session);

/* Parses the internal tls fragment */
int parse_handshake(int conn, unsigned char *fragment, struct tlsSession *ssl);

int parse_alert_message(unsigned char *fragment);

/* Parse the tls client hello message */
int parse_client_hello(unsigned char *message, struct tlsSession *session);

int generate_server_keys(struct tlsSession *session);

int curve25519_mult(unsigned char *a, unsigned char *out);

int i32_add(unsigned char *a, unsigned char *b, unsigned char *out);

int send_alert_message(int conn, int mess_code);

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

short parse_encrypt_then_mac_ext(unsigned char **msg);

short parse_master_secret_ext(unsigned char **msg, struct tlsSession *ses);

short parse_session_ticket_ext(unsigned char **msg);

short parse_suported_versions_ext(unsigned char **msg, struct tlsSession *ses);

short parse_key_exchange_modes_ext(unsigned char **msg);

short parse_key_share_ext(unsigned char **msg, struct tlsSession *session);

short parse_renegotiation_ext(unsigned char **msg, struct tlsSession *ses);

short parse_unknown_ext(unsigned char **msg);

int write_renegotiation_ext(unsigned char *buff);

int write_key_share_ext(unsigned char *buff, struct tlsSession session);

int write_supported_versions_ext(unsigned char *buff);

int write_master_secret_ext(unsigned char *buff);

#endif
