/*
 * ****************************************************************************
 *
 * PROJECT:     Maze
 *
 * TITLE:       Simple HTTP 1.1 web browser.
 *
 * FUNCTION:    This is the main file, here we manage to open TCP connections
 *              in order to connect to an URL. Then each connection is proces -
 *              sed by a different thread, created by a fork command, that will
 *              write the request, wail for a response and interpret it, and 
 *              generate the page.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:       
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ****************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "connect.h"

int main(void){

    puts("Please enter a valid address.");













    puts("End of program.");
    return 0;
}

