/*
 *  This is the function that sends the file requested in a response, it takes
 *  two arguments: the client's connection and the file requested in the GET
 *  message.
 */

#ifndef GETFN_H
#define GETFN_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <web.h>

/* Declare external variables */
extern unsigned char *PATH;

/* Receives client's parameters and sends a file */
int serve_get(unsigned int conn, struct response res);

#endif
