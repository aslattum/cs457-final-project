/*----------------------------------------------------------------------------
Final-Project: Needham-Scroeder Protocol

FILE:   myCrypto.c

Written By:
     1- Adam Slattum

Submitted on: 12/3/17
----------------------------------------------------------------------------*/

#include "myCrypto.h"
#define CIPHER_LEN_MAX 1024
#define PLAINTEXT_LEN_MAX (CIPHER_LEN_MAX-16)

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

//-----------------------------------------------------------------------------
int encrypt( unsigned char *plaintext, int plaintext_len, unsigned char *key,
			 unsigned char *iv, unsigned char *ciphertext )
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
 
	/* Create and initialise the context */
	if( !(ctx = EVP_CIPHER_CTX_new()) )
 		handleErrors("Error");
 	
	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
		handleErrors("Error");
 
	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) )
		handleErrors("Error");
	ciphertext_len = len;

	//printf("Before EncryptFinal:\n");
	//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
 
	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) )
		handleErrors("Error");
	ciphertext_len += len;

	//printf("After EncryptFinal:\n");
	//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
 
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

//-----------------------------------------------------------------------------
int decrypt( unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
 			 unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
 
	/* Create and initialise the context */
	if( !(ctx = EVP_CIPHER_CTX_new()) )
		handleErrors("Error");

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
		handleErrors("Error");
	
	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) )
		handleErrors("Error");
	plaintext_len = len;
 
	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if( 1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len) )
		handleErrors("Error");
 	plaintext_len += len;
 
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

//-----------------------------------------------------------------------------
int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
  EVP_CIPHER_CTX *ctx;
  int len, ciphertext_len;
  char plaintext[PLAINTEXT_LEN_MAX];
  char ciphertext[CIPHER_LEN_MAX];

  /* Create and initialise the context */
  if( !(ctx = EVP_CIPHER_CTX_new()) )
      handleErrors("Error");

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
  * and IV size appropriate for your cipher
  * In this example we are using 256 bit AES (i.e. a 256 bit key). The
  * IV size for *most* modes is the same as the block size. For AES this
  * is 128 bits */
  if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
      handleErrors("Error");

  /* Continuously loop until no more plaintext can be read, 
     encrypting along the way
  */ 
  while ( 1 ) 
  {
    int nbytes = read( fd_in, plaintext, PLAINTEXT_LEN_MAX ) ; 
    if ( nbytes <= 0 ) 
        break ;

    /* Provide the message to be encrypted, and obtain the encrypted output.*/
    if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, nbytes ) ) 
        handleErrors("Error");
    ciphertext_len += len;
    write( fd_out, (const char *) ciphertext, len );
    memset( ciphertext, 0, sizeof(ciphertext) );
    memset( plaintext, 0, sizeof(plaintext) );
  }

  /* Finalise the encryption. Further ciphertext bytes may be written at
  * this stage.
  */
  if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len) )
      handleErrors("Error");

  write( fd_out, (const char*) ciphertext, len );
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
  EVP_CIPHER_CTX *ctx;
  int len, plaintext_len;
  char plaintext[PLAINTEXT_LEN_MAX];
  char ciphertext[CIPHER_LEN_MAX];

  /* Create and initialise the context */
  if( !(ctx = EVP_CIPHER_CTX_new()) )
      handleErrors("Error");

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
  * and IV size appropriate for your cipher
  * In this example we are using 256 bit AES (i.e. a 256 bit key). The
  * IV size for *most* modes is the same as the block size. For AES this
  * is 128 bits */
  if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
      handleErrors("Error");

  /* Provide the message to be decrypted, and obtain the plaintext output.
  * EVP_DecryptUpdate can be called multiple times if necessary
  */
  while ( 1 ) 
  {
    int nbytes = read( fd_in, ciphertext, CIPHER_LEN_MAX) ;
    if ( nbytes <= 0 ) 
        break ;

    if ( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, nbytes ) ) 
        handleErrors("Error");
    plaintext_len += len;
    write( fd_out, plaintext, len ) ; 
    memset( ciphertext, 0, sizeof(ciphertext) ) ; 
    memset( plaintext, 0, sizeof(plaintext) ) ; 
  }   

  /* Finalise the decryption. Further plaintext bytes may be written at
  * this stage.
  */
  if( 1 != EVP_DecryptFinal_ex(ctx, plaintext, &len) )
      handleErrors("Error");

  write( fd_out, plaintext, len ) ; 
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

