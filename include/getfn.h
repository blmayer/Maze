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
#include "header.h"
#include "auxfns.h"

/* Receives client's parameters and sends a file */
int serve_get(int conn, struct header req, int encrypted);

#endif

