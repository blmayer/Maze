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
#include "header.h"
#include "auxfns.h"

/* Receives conection's parameters and server a header */
int serve_head(int conn, struct header req, int encrypted);

#endif

