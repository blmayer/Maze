/*
 *  This is the function that elaborates the header of a response, it takes two
 *  arguments: the client's connection and the file requested in the HEAD messa-
 *  ge.
 */

#ifndef HEADFN_H_INCLUDED
#define HEADFN_H_INCLUDED

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <webng.h>
#include "aux.h"

/* Receives connection's parameters and server a header */
short serve_head(short conn, struct response res);

#endif

