/*
 *  This is the file that defines our structures used in our functions, here
 *  we have the cryptographic key, encrypting requests; the request struct
 *  to hold the information pertaining to a request; and the response struct
 *  holding the response information.
 */

#ifndef WEBNG_H
#define WEBNG_H

#include <sys/ioctl.h>
#include <sys/poll.h>

/*
 * Objects definitions
 */

/* Our structure that contains the response's data */
struct response {
	short status;
	char *stext;
	char *type;
	char *path;
	float vers;
	char *serv;
	char *date;
	char *conn;
	char *auth;
	char *cenc;
	char *ctype;
	int clen;
	char *ttype;
	char *body;
};

/* Our structure that contains the request's data */
struct request {
	char *type;
	char *url;
	float vers;
	char *host;
	char *conn;
	char *user;
	char *auth;
	char *cenc;
	char *ctype;
	int clen;
	char *ttype;
	char *body;
};

struct url {
	char *proto;
	char *ip;
	char *port;
	char *domain;
	char *path;
	char *pars;
};

/*
 * Function prototypes
 */

/* Reads data in chunked format from a socket */
void read_chunks(int conn, char *body);

/* Just wait for socket to become ready to read */
int get_ready_bytes(int conn);

/* Reads data in the HTTP header format from a socket */
int get_message(int conn, char **buffer, int buff_start);

/* Extracts a token from a string */
char *get_token(char *source, char *par);

/* Extracts the path from an URL */
short parse_URL(char *url, struct url *addr);

/* Parses a string and populates the request structure */
short parse_request(char *message, struct request *req);

/* Parses a string and populates the response structure */
short parse_response(char *message, struct response *res);

/* Calculates a request header size */
short req_header_len(struct request req);

/* Creates a HTTP header string */
short create_req_header(struct request req, char *dest);

/* Calculates a response header size */
short res_header_len(struct response res);

/* Creates a response with header and optional body */
short create_res_header(struct response res, char *dest);

/* Parses a list of numbers from a string to an array */
short *split_keys(char *key_list);

/* Reads a message and encodes it */
// void encode(char *message, char *key);

/* Reads an encrypted message and decodes it */
// void decode(char *cypher, char *key);

#endif
