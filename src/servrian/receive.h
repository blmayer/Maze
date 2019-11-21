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
#include <webng.h>
#include "head.h"
#include "get.h"

/* Global variables from server.c (path to the webpages folder and key) */
extern char *PATH;

/* This function reads the header and passes it to the right function */
short send_response(int cli_conn);

#endif
