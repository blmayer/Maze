/*
 *  This are the functions responsible for encoding and decoding strings.
 */

#ifndef TRANSFORM_H
#define TRANSFORM_H

#include <stdio.h>
#include <string.h>
#include "headers.h"

// Encode a string
unsigned char *encode(unsigned char *message);

// Decode a string
unsigned char *decode(unsigned char *cipher);

#endif

