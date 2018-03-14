/*
 *  This is the function that will process the file requested in a POST, it
 *  takes three arguments: the client's connection, the file requested in the
 *  message and the connection type: ("Keep-Alive", or "Close"). The endpoint
 *  chosen will determine what script (function) would handle the request.
 */

#ifndef POSTFN_H
#define POSTFN_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "header.h"
#include "auxfns.h"

// This function responds to a POST request
int handle_post(int conn, struct header req, int encrypted);

#endif

