/*
 * ****************************************************************************
 *
 * PROJECT:     Servrian
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
#include "login.h"

int serve_get(int conn, struct header req, int encrypted){
    
    /* Authentication happens here */
    req.auth = get_token(req.rest, "Authorization: ");

    /* If the user sends the token respond with encrypted version, if ok */
    if(req.auth != NULL){
        
        /* Check authorization cases */
        switch(authorization(req.auth)) {
            case 0:
                /* User is authorized, proceed */
                req.status = 200;
                break;
            case 1:
                /* Wrong password, redirect to login page */
                req.status = 401;
                req.path = "webpages/login.html";
                break;
            case -1:
                /* User is not registered, subscribe page */
                req.status = 403;
                req.path = "webpages/subscribe.html";
                break;
            case -2:
                /* Browser requested an unsupported method */
                req.status = 501;
                req.path = "webpages/501.html";
                break;
            case -3:
                /* An error occured */
                req.status = 500;
                req.path = "webpages/500.html";
                break;
        }
    }

    /* Open the file for reading */
    FILE *page_file = fopen(req.path, "rb");

    if(page_file == NULL){
        /* Something went wrong, problably file was not found */
        req.status = 404;
        page_file = fopen("webpages/404.html", "r");
    } else {
        /* File found */
        req.status = 200;
    }

    fseek(page_file, 0, SEEK_END);      /* Seek to the last byte of the file */
    int page_size = ftell(page_file);   /* The SEEK position is the file size */
    rewind(page_file);                  /* Go back to the start of the file */
    
    /* Read it all in one operation and close */
    unsigned char buff[page_size + 1];
    fread(buff, page_size, sizeof(unsigned char), page_file);
    fclose(page_file);                  /* Close the file */
    buff[page_size] = 0;                /* Add the terminating zero */
    req.body = strdup(buff);

    /* Change our header parameters */
    req.clen = page_size;

    /* Verify the connection and request version */
    if(req.conn == NULL && strcmp(req.vers, "HTTP/1.1") == 0) {
        req.conn = "keep-alive";
    } else {
        req.conn = "close";
    }

    /* Update the content type line */
    req.cenc = mime_type(req.path);

    /* Create the head */
    char *response = create_response(req, encrypted);

    /* Send the response */
    write(conn, response, strlen(response));
    
    printf("\tFile %s served.\n", req.path);
    
    return 0;
}

