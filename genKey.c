/*
 Generate encryption key / IV and save to binary files
*/
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void main()
{
	uint8_t amal_key[EVP_MAX_KEY_LENGTH] ,
			basim_key[EVP_MAX_KEY_LENGTH] ,
			amal_iv[EVP_MAX_IV_LENGTH] ,
			basim_iv[EVP_MAX_IV_LENGTH] ;

	unsigned amal_key_len = EVP_MAX_KEY_LENGTH ;
	unsigned basim_key_len = EVP_MAX_KEY_LENGTH ;
	unsigned amal_iv_len = EVP_MAX_IV_LENGTH ;
	unsigned basim_iv_len = EVP_MAX_IV_LENGTH ;
	
	int amal_fd_key, amal_fd_iv, basim_fd_key, basim_fd_iv ;
	amal_fd_key = open("kdc/amal_key.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;
  	if( amal_fd_key == -1 )
  	{
    	fprintf(stderr, "Unable to open file for key\n");
    	exit(-1) ;
  	}
  	amal_fd_iv = open("kdc/amal_iv.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;
  	if( amal_fd_iv == -1 )
  	{
    	fprintf(stderr, "Unable to open file for IV\n");
    	exit(-1) ;
  	}
    basim_fd_key = open("kdc/basim_key.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;
    if( basim_fd_key == -1 )
    {   
        fprintf(stderr, "Unable to open file for key\n");
        exit(-1) ;
    }
    basim_fd_iv = open("kdc/basim_iv.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;
    if( basim_fd_iv == -1 )
    {   
        fprintf(stderr, "Unable to open file for IV\n");
        exit(-1) ;
    }

  	// Genrate Amal random key & IV
  	RAND_bytes( amal_key , amal_key_len );
  	RAND_bytes( amal_iv , amal_iv_len );

	// Generate Basim random key & IV
	RAND_bytes( basim_key , basim_key_len );
    RAND_bytes( basim_iv , basim_iv_len );

  	write( amal_fd_key , amal_key , amal_key_len );
  	write( amal_fd_iv , amal_iv , amal_iv_len );
	
	write( basim_fd_key , basim_key , basim_key_len );
    write( basim_fd_iv , basim_iv , basim_iv_len );

  	close( amal_fd_key  ) ;
  	close( amal_fd_iv   ) ;
	close( basim_fd_key ) ;
	close( basim_fd_iv  ) ;
}
