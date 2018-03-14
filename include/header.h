/*
 *  This is the function that sends the file requested in a response, it takes
 *  two arguments: the client's connection and the file requested in the GET
 *  message.
 */

#ifndef HEADER_H_INCLUDED
#define HEADER_H_INCLUDED

#define KEY "Ie70tGt3A2TYntzomlrdQqxlZjWm92AcRKcoOLflbMckfnN9oLUqK9zI0y4wDyJk"\
            "RFX4ECITyLGfnO2ZwVd0hcp0Yel6F6fuFIaoOIomyW3AXEICZWzV7br9eghUsCHx"\
            "JRd3s1G0Y9UCwgiMIZTIqeLLRIplgk1WSnwtvcGEE48CHMnubye4TKbAMevftjfA"\
            "3BDuIlc2Ka4LK67ZCWwaftAbRBEOBz6uHAhy0qSf9PIeSFZITm5biznN3PaolkuP"\
            "nHUcbsng9Wvp7K2QMTL3wOceBvmwXOvRONReyShCMEMkytRj1HC08683oudaPS5T"\
            "fBrRG1kpt9ksUn2fpmlqXAyr2EdPTHd8FqO9WWnFPtnSDQbzrtpRoso3MCiJZKKO"\
            "Tlz6KyzMXwB2IdAQdXlTuxbhWXV0MlDoTxpsnxZLXAiyBmDd2LKTaJ1e8NKLW5sE"\
            "rdsjcmKgKUYIK7qoyq1DDiCrSVcDbWFrBrnTqrUOTNaQGk7GpwiTEIwtSNAecEDB"

// Our structure that contains the request's data
struct header {
    char *type;
    char *path;
    int status;
    char *vers;
    char *conn;
    char *auth;
    int cryp;
    char *cenc;
    int clen;
    char *rest;
    char *body;
};

#endif

