/*
 * ****************************************************************************
 *
 * PROJECT:     Maze
 *
 * TITLE:       Auxiliary Functions
 *
 * FUNCTIONS:   
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:       This is the function that sends the file requested in a 
 *              response, it takes two arguments: the client's connection and 
 *              the file requested in the GET message.
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ****************************************************************************
 */

#include "getfn.h"

int send_get(int conn, struct request req, int encrypted){

    /* Verify the connection and request version */
    if(req.conn == NULL && strcmp(req.vers, "1.1") == 0){
        req.conn = "Keep-Alive";
    }

	/* Client identification */
    req.user = "Maze/<VERSION> (x86_64)";
	
	/* Accept encoding */
	req.cenc =  "*/*";
	
    /* Create the head */
    char *request = create_request(req, encrypted);

    /* Send the request */
    write(conn, request, strlen(request));
    
    puts("\tGET request sent.\n");
    
	puts(request);
    
	return 0;
}

