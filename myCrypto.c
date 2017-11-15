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
#define INPUT_CHUNK   16384

size_t fileDigest( int fd_in , uint8_t *digest , int fd_save )
// Read all the incoming data from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_save' is > 0, store a copy of the incoming data to 'fd_save'
// Returns actual size in bytes of the computed hash value
{
    int  mdLen;
    unsigned int bytes_len;
    EVP_MD_CTX *ctx;

    //Create and initialise the context
    if( !(ctx = EVP_MD_CTX_create()) )
    {
        handleErrors("Error in context creation");
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(EVP_DigestInit(ctx, EVP_sha256()) != 1)
    {
        handleErrors("Error in context initialization");
    }

    char buffer[INPUT_CHUNK];
    while ((bytes_len = read(fd_in, buffer, INPUT_CHUNK)) > 0)
    {
        //Provide the message to be encrypted, and obtain the encrypted output.
        if(EVP_DigestUpdate(ctx, buffer, bytes_len) != 1)
        {
            handleErrors("Error in updating the digest");
        }
        if (fd_save > 0)
        {
            write(fd_save, buffer, bytes_len);
        }
    }
    //Finalise the encryption
    if(EVP_DigestFinal(ctx, digest, &mdLen) != 1)
    {
        handleErrors("Error in finalizing the digest");
    }

    //Clean up
    EVP_MD_CTX_destroy(ctx);

    return mdLen;
}

//-----------------------------------------------------------------------------
RSA * getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");

    if (fp == NULL)
    {
        printf("Unable to open RSA key file %s \n",filename);
        return NULL;
    }

    RSA *rsa = RSA_new() ;

    if ( public )
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    else
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);

    fclose( fp );
    return rsa;
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

//-----------------------------------------------------------------------------
void elgamalSign(const uint8_t *digest, int len, const BIGNUM *q,
                 const BIGNUM *gen, const BIGNUM *x, BIGNUM *r, BIGNUM *s,
                 BN_CTX *ctx)
{
    BIGNUM *k = BN_new();
    BIGNUM *result = BN_new();
    BIGNUM *q_minus_one = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *k_inverse = BN_new();
    BIGNUM *x_times_r = BN_new();
    BIGNUM *digest_minus_xr = BN_new();
    BIGNUM *digest_bn = BN_new();

    BN_bin2bn(digest, len, digest_bn);
    BN_dec2bn(&one, "1");
    BN_sub(q_minus_one, q, one);

    //select random integer k: 1 < k < q-1 and gcd(k, q-1)=1
    do {
        k = BN_myRandom(q);
        BN_gcd(result, k, q_minus_one, ctx);
    } while (BN_is_one(result) == 0);

    //r = gen^k mod q
    BN_mod_exp(r, gen, k, q, ctx);

    //k^-1
    BN_mod_inverse(k_inverse, k, q_minus_one, ctx);

    //x * r
    BN_mul(x_times_r, x, r, ctx);

    //digest - (x * r)
    BN_sub(digest_minus_xr, digest_bn, x_times_r);

    //s = k_inverse * (digest_minus_xr) mod q-1
    BN_mod_mul(s, k_inverse, digest_minus_xr, q_minus_one, ctx);
}

//-----------------------------------------------------------------------------
int elgamalValidate(const uint8_t *digest, int len, const BIGNUM *q,
                    const BIGNUM *gen, const BIGNUM *y, BIGNUM *r, BIGNUM *s,
                    BN_CTX *ctx)
{
    BIGNUM *v1 = BN_new();
    BIGNUM *v2 = BN_new();
    BIGNUM *y_raised_to_r = BN_new();
    BIGNUM *r_raised_to_s = BN_new();
    BIGNUM *digest_bn;

    digest_bn = BN_bin2bn(digest, len, NULL);

    //verify 1 < r < q-1
    

    //v1 = gen^digest mod q
    BN_mod_exp(v1, gen, digest_bn, q, ctx);

    //y^r
    BN_mod_exp(y_raised_to_r, y, r, q, ctx);

    //r^s
    BN_mod_exp(r_raised_to_s, r, s, q, ctx);

    //v2 = y^r * r^s mod q
    BN_mod_mul(v2, y_raised_to_r, r_raised_to_s, q, ctx);

    //Check v1 == v2
    if (BN_cmp(v1, v2) == 0) {
        return 1;
    } else {
        return 0;
    }
}

