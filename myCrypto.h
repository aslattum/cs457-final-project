/*----------------------------------------------------------------------------
PA-03: Big Integers & Elgamal Digital Signatures using openSSL.
Written By:
     1- Dr. Mohamed Aboutabl
Submitted on: 11//17
----------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

void     handleErrors( char *msg) ;
int      BN_write_fd(const BIGNUM *bn, int fd_out);
BIGNUM * BN_read_fd(int fd_in);
BIGNUM * BN_myRandom(const BIGNUM *p);
int      encrypt( unsigned char *plaintext, int plaintext_len, unsigned char *key,
         		  unsigned char *iv, unsigned char *ciphertext );
int 	 decrypt( unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
             	  unsigned char *iv, unsigned char *plaintext);
int      encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv );
int      decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv );
