/*
 * ****************************************************************************
 *
 * PROJECT:     Servrian
 *
 * TITLE:       Functions to encrypt and decrypt requests
 *
 * FUNCTION:    In order to create a more secure transmission all requests will
 *              be encripted to be sent and decrypted when received. Here we
 *              transalte characters using some method.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ****************************************************************************
 */

#include "transform.h"

unsigned char *encode(unsigned char *message){

    /* Get length of received message */
    int n = strlen(message) + 1;        // Add the terminating zero place
    int i = 0;
    unsigned char cipher[n];
    
    while(i < n){
        cipher[i] = (message[i] ^ KEY[i % 512]) + 1;    // +1 to never get 0
        i++;
    }

    cipher[n] = 0;      // Add terminating zero
    return strdup(cipher);
}

unsigned char *decode(unsigned char *cipher){

    /* Get length of received message */
    int n = strlen(cipher) + 1;        // Add the terminating zero place
    int i = 0;

    unsigned char message[n];
    
    while(i < n){
        message[i] = (cipher[i] - 1) ^ KEY[i % 512];
        i++;
    }

    message[n] = 0;      // Add terminating zero

    return strdup(message);
}

