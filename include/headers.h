/*
 *  This is the file that defines our structures used in our functions, here
 *  we have the cryptographic key, encrypting requests; the request struct
 *  to hold the information pertaining to a request; and the response struct
 *  holding the response information.
 */

#ifndef HEADERS_H
#define HEADERS_H

/* Our structure that contains the response's data */
struct response {
    int status;
    char *type;
    char *path;
    char *vers;
    char *conn;
    char *auth;
    char *key;
    char *cenc;
    int clen;
    char *body;
};

/* Our structure that contains the request's data */
struct request {
    char *type;
    char *url;
	char *vers;
    char *host;
    char *conn;
    char *user;
    char *auth;
    char *key;
    char *cenc;
    int clen;
    char *body;
};

#endif
