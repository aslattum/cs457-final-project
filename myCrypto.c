/*----------------------------------------------------------------------------
Final-Project: Needham-Scroeder Protocol

FILE:   myCrypto.c

Written By:
     1- Adam Slattum

Submitted on: 12/3/17
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
int BN_write_fd(const BIGNUM *bn, int fd_out)
{
    int bnSize = BN_num_bytes(bn);
    if (write(fd_out, &bnSize, sizeof(int)) < 0) { //Send #of bytes
        return 0;
    }

    unsigned char *bytes = malloc((bnSize+1) * sizeof(char));
    bytes[bnSize] = '\0';

    BN_bn2bin(bn, bytes);
    if (write(fd_out, bytes, bnSize) < 0) { //Send bytes of BIGNUM
        return 0;
    }
    return 1; //Success
}

//-----------------------------------------------------------------------------
BIGNUM * BN_read_fd(int fd_in)
{
    int bnSize;
    if (read(fd_in, &bnSize, sizeof(int)) < 0) {
        return NULL;
    }

    unsigned char *bytes = malloc((bnSize+1) * sizeof(char));
    bytes[bnSize] = '\0';
    if (read(fd_in, bytes, bnSize) < 0) {
        return NULL;
    }

    BIGNUM *bn;
    bn = BN_bin2bn(bytes, bnSize, NULL);

    return bn;
}

//-----------------------------------------------------------------------------
BIGNUM * BN_myRandom(const BIGNUM *p)
{
    BIGNUM *bn = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *four = BN_new();
    BIGNUM *result = BN_new();
    BIGNUM *p_minus_four = BN_new();

    BN_dec2bn(&two, "2");
    BN_dec2bn(&four, "4");

    BN_sub(p_minus_four, p, four); //p-4
    BN_rand_range(bn, p_minus_four); //in range [0, p-4]
    BN_add(result, bn, two); //add two to put in range [2, p-2]
    return result;
}