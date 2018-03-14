/*
 * ****************************************************************************
 *
 * PROJECT:     Servrian
 *
 * TITLE:       The function spawns when an user is connected.
 *
 * FUNCTION:    This is the main response function, it is called when a user
 *              connects and should elaborate a response or discard the client
 *              if it doesn't communicate correctly. The function receives the
 *              client socket descriptor as argument, it then reads the mes -
 *              sage from this user and interprets it. Then it passes those
 *              arguments to the proper response handler.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ****************************************************************************
 */

#include "receivefn.h"

int send_response(int cli_conn){
    
    /* Set the socket timeout */
    struct timeval timeout = {180, 0};         /* Timeout structure: 3 mins */
    setsockopt(cli_conn, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, 18);
 
    receive:

    /* Initialize variables for reading the request */
    puts("\tReady to receive.");
    int pos = 0, buff_size = 1024;
    unsigned char *buffer = calloc(buff_size, 1);
    unsigned char *dec_buffer = calloc(buff_size, 1);

    /* This is a loop that will read the data comming from our connection */
    while(read(cli_conn, buffer + pos, 1) == 1){
        
        /* Decode while we read */
        dec_buffer[pos] = (buffer[pos] - 1) ^ KEY[pos % 512];
        
        /* Increase pos by 1 to follow the buffer size */
        pos++;
        
        /* The only thing that can break our loop is a blank line */
        if(strcmp(buffer + pos - 4, "\r\n\r\n") == 0){ 
            break;
        }
        
        if(pos == buff_size){
            puts("\t\tBuffer grew.");
            buff_size += 512;
            buffer = realloc(buffer, buff_size);
            dec_buffer = realloc(dec_buffer, buff_size);
        }
    }

    /* Split first line to get our parameters */
    char *verb = strtok(buffer, " ");    /* First token is the method */
    char *dec_verb;                      /* First token is the method */
    char *header;                        /* The placeholder for request */
    struct header request;               /* Create our header structure */
    int encrypted = 0;                   /* Encrypted resquest flag */
    
    /* Check if this is a valid request */
    switch(strcmp(verb, "PEZ")){
        case -8:
        
        case -9:
        
        case 10:
            puts("\tGot a non-encrypted request.");
            free(dec_buffer);
            request.type = strdup(verb);
            header = strdup(strtok(NULL, ""));
            free(buffer);
            break;
        
        default:
            puts("\tMay be an encoded request.");
            free(buffer);
            dec_verb = strtok(dec_buffer, " ");
            /* Check if this is a valid encrypted request */
            switch(strcmp(dec_verb, "PEZ")){
                case -8:
                
                case -9:
                
                case 10:
                    puts("\tGot a non-encrypted request.");
                    free(buffer);
                    encrypted = 1;
                    request.type = strdup(dec_verb);
                    header = strdup(strtok(NULL, ""));
                    free(dec_buffer);
                    break;
                
                default:
                    puts("\tReceived an invalid request.");
                    free(dec_buffer);
                    return -1;
            }
        
    } 

    /* Now we extract the information we need */
    
    /* Get the other parameters */
    request.path = strtok(header, " ");       
    request.vers = strtok(NULL, "\r\n");   
    request.rest = strtok(NULL, "");
    request.conn = get_token(request.rest, "Connection: ");
    
    /* Jump to the last / for security and prepend webpages */
    request.path = strrchr(request.path, '/');

    /* Prepend webpages to the path, this simplifies a lot */
    if(strcmp(request.path, "/") == 0){
        request.path = "webpages/index.html";   /* Our root is the index page */
    } else {
        char temp[strlen(request.path) + 9];
        strcpy(temp, "webpages");
        strcat(temp, request.path);
        request.path = strdup(temp);
    }

    /* Process the request with the correct method */
    switch(strcmp(request.type, "PEZ")){
        case -8:
            puts("\tReceived HEAD");
            if(serve_head(cli_conn, request, encrypted) < 0){
                perror("\tUnable to respond");
                return -1;
            }
            puts("\tResponse sent.");
            break;
        
        case -9:
            puts("\tProcessing GET request...");
            if(serve_get(cli_conn, request, encrypted) < 0){
                perror("\tA problem occured");
                return -1;
            }
            puts("\tResponse sent.");
            break;
        
        case 10:
            puts("\tProcessing POST request...");
            if(handle_post(cli_conn, request, encrypted) < 0){
                perror("\tA problem occured");
                return -1;
            }
            puts("\tPOST processed.");
            break;
        
        default:
            puts("\tProcessing unsupported request...");
            request.status = 400;
            char *ni_head = create_response(request, encrypted);
            write(cli_conn, ni_head, strlen(ni_head));
            puts("\tBad request, sending 400.");
    }
    
    /* Close connection depending on the case */
    if(request.conn != "close" || strcmp(request.vers, "HTTP/1.1") == 0){
        puts("\tReceiving again...");
        goto receive;
    }
    
    return 0;
}

