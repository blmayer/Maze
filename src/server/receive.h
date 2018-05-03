/*
 *  This is the main response function, it is called when a user connects and
 *  should elaborate a response or discard the client if it doesn't communicate
 *  correctly. The function receives the client socket descriptor as argument,
 *  it then reads the message from this user and interprets it. Then it passes
 *  those arguments to the proper response handler.
 */

#ifndef RECEIVEFN_H
#define RECEIVEFN_H

#include <sys/socket.h>
#include <unistd.h>
#include <web.h>
#include "headfn.h"
#include "getfn.h"
#include "postfn.h"

/* Global variables from server.c (path to the webpages folder and key) */
extern unsigned char *PATH;
extern unsigned char *KEY;
extern unsigned char *VERSION;

/* This function reads tne header and passes it to the right function */
int send_response(unsigned int cli_conn);

#endif

