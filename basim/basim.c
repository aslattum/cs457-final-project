/*----------------------------------------------------------------------------
Final-Project: Needham-Schroeder Protocol 

FILE:   basim.c

Written By: 
     1- Adam Slattum 
     
Submitted on: 12/3/17 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"
#define CIPHER_LEN_MAX 5000
int main ( int argc , char * argv[] )
{
    
    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 4 )
    {
        printf("Missing command-line arguments\n") ;
        exit(-1) ;
    }
    int AtoB_ctrl = atoi( argv[1] ) ;
    int AtoB_data = atoi( argv[2] ) ;
	int BtoA_ctrl = atoi( argv[3] ) ; 

    // Open the log file
    FILE *log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Basim. Will receive from Amal on FD %d\n", AtoB_ctrl);
	fprintf( log , "This is Basim. Will write to Amal on FD %d\n", BtoA_ctrl);
	fprintf( log , "This is Basim. Will read the bunny file from FD %d\n" , AtoB_data);

    /* Step 3 of Protocol */
	fprintf(log, "\n---- Step 3 of Protocol ----\n");

	unsigned key_len = 32; // i.e. 256 bits
    unsigned iv_len = 16; // i.e. 128 bits

	// uint8_t arrays to hold basim's key and iv
	uint8_t basimKey[EVP_MAX_KEY_LENGTH];
    uint8_t basimIV[EVP_MAX_KEY_LENGTH];

	int fd_basim_key, fd_basim_iv;
	// get the basim key and iv
    fd_basim_key = open("basim/basim_key.bin" , O_RDONLY ) ; 
    if (fd_basim_key < 0) {
        fprintf(log, "ERROR OPENING BASIM KEY\n");
    }   
    read ( fd_basim_key , basimKey , key_len ) ; 
    close( fd_basim_key ) ; 
    fd_basim_iv = open("basim/basim_iv.bin" , O_RDONLY ) ; 
    if (fd_basim_iv < 0) {
        fprintf(log, "ERROR OPENING BASIM IV\n");
    }   
    read ( fd_basim_iv , basimIV , iv_len ) ; 
    close( fd_basim_iv ) ;	

	// get step3 message total size
	uint8_t step3_totalSize[sizeof(int)];
	read(AtoB_ctrl, step3_totalSize, sizeof(int));
	int step3_totalLength = atoi(step3_totalSize);

	// read the total message into an array
	uint8_t step3_message[step3_totalLength];
	read(AtoB_ctrl, step3_message, step3_totalLength);
	
	uint8_t step3_encrSize[sizeof(int)];
	int step3_offset = 0;

	// read in the size of the encypted message
	memcpy(step3_encrSize, step3_message + step3_offset, sizeof(int));
	step3_offset += sizeof(int);
	
	// read in the encrypted message
	int step3_encrLength = atoi(step3_encrSize);
	uint8_t step3_encrMsg[step3_encrLength];
	memcpy(step3_encrMsg, step3_message + step3_offset, step3_encrLength);
	
	// decrypt the message
    uint8_t step3_plaintext[CIPHER_LEN_MAX];
    int innerNumDecrypted = decrypt( step3_encrMsg, step3_encrLength, basimKey, basimIV, step3_plaintext);		
	step3_offset += step3_encrLength;			
	
	// read in the size of the nonce		
	uint8_t step3_nonce2Size[sizeof(int)];
	memcpy(step3_nonce2Size, step3_message + step3_offset, sizeof(int));
	step3_offset += sizeof(int);

	// read in the nonce
	int step3_nonce2Length = atoi(step3_nonce2Size);
	uint8_t nonce2[step3_nonce2Length];
	memcpy(nonce2, step3_message + step3_offset, step3_nonce2Length);
	BIGNUM* step3_Na2 = BN_new();
    BN_bin2bn(nonce2, step3_nonce2Length, step3_Na2);

	// read the information from the decrypted message
	int step3_decr_offset = 0;
	
	// get the inner size of the plaintext
	uint8_t step3_innerSize[sizeof(int)];
	memcpy(step3_innerSize, step3_plaintext + step3_decr_offset, sizeof(int));
	int step3_innerLength = atoi(step3_innerSize);
	step3_decr_offset += sizeof(int);

	// get the session key length
	uint8_t step3_KsKey_Size[sizeof(int)];
	memcpy(step3_KsKey_Size, step3_plaintext + step3_decr_offset, sizeof(int));
	int step3_KsKey_Length = atoi(step3_KsKey_Size);
	step3_decr_offset += sizeof(int);

	// get the sesion key
	uint8_t sessionKey[step3_KsKey_Length];
	memcpy(sessionKey, step3_plaintext + step3_decr_offset, step3_KsKey_Length);
	step3_decr_offset += step3_KsKey_Length;	

	// get the sesion iv length
	uint8_t step3_KsIV_Size[sizeof(int)];
	memcpy(step3_KsIV_Size, step3_plaintext + step3_decr_offset, sizeof(int));
	int step3_KsIV_Length = atoi(step3_KsIV_Size);
	step3_decr_offset += sizeof(int);
	
	// get the session iv
	uint8_t	sessionIV[step3_KsIV_Length];
	memcpy(sessionIV, step3_plaintext + step3_decr_offset, step3_KsIV_Length);
	step3_decr_offset += step3_KsIV_Length;

	// get the IDa length
	uint8_t step3_IDa_Size[sizeof(int)];
	memcpy(step3_IDa_Size, step3_plaintext + step3_decr_offset, sizeof(int));
	int step3_IDa_Length = atoi(step3_IDa_Size);
	step3_decr_offset += sizeof(int);

	// get the IDa
	uint8_t step3_IDa[step3_IDa_Length];
	memcpy(step3_IDa, step3_plaintext + step3_decr_offset, step3_IDa_Length);
	 

	fprintf(log, "Read from Amal the Ks key, Ks iv, IDa, and Na2\n");
	fprintf(log, "Hexdump of Ks Key:\n");
	BIO_dump_fp (log, (const char *) sessionKey, step3_KsKey_Length);
	fprintf(log, "Hexdump of Ks IV:\n");
    BIO_dump_fp (log, (const char *) sessionIV, step3_KsIV_Length);	
	fprintf(log, "IDa: %s\n", step3_IDa);
	fprintf(log, "Na2: %s\n", BN_bn2hex(step3_Na2)); 	

	EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;  
    close( AtoB_ctrl ) ;
	close( BtoA_ctrl ) ;
    close( AtoB_data ) ;

    return 0 ;
}

