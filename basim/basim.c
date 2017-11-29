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

	// Open the file that we will send
    int fd_bunny = open("basim/bunny.mp4" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ;
    if( fd_bunny == -1 )
    {
        fprintf( stderr , "This is Basim. Could not open input file\n");
        exit(-1) ;
    }


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
	fprintf(log, "\n---- Message 3 of Protocol ----\n");

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
	BIO_dump_fp (log, (const char *) sessionKey, key_len);
	fprintf(log, "Hexdump of Ks IV:\n");
    BIO_dump_fp (log, (const char *) sessionIV, step3_KsIV_Length);	
	fprintf(log, "IDa: %s\n", step3_IDa);
	fprintf(log, "Na2: %s\n", BN_bn2hex(step3_Na2)); 	


	/* Step 4 of Protocol */
    fprintf(log, "\n---- Message 4 of Protocol ----\n");
	BN_CTX *ctx = BN_CTX_new();
    BIGNUM *Nb = BN_new();
    BIGNUM *range = BN_new();

    // craete two and 64 random nums to do 2^64 range for random num
    BIGNUM *two = BN_new();
    BIGNUM *sixty_four = BN_new();
    BN_dec2bn(&two, "2");
    BN_dec2bn(&sixty_four, "64");

    // create the range for the random num
    BN_exp(range, two, sixty_four, ctx);

    // create the random nonce Na
    BN_rand_range(Nb, range);		

	// create array to hold the BIGNUM
	int nonceBLength = BN_num_bytes(Nb);
    uint8_t nonceB[nonceBLength];
	
	// transform big num into binary
	BN_bn2bin(Nb, nonceB);	

	// compute the function of Na2
	BIGNUM* function_Na2 = BN_new();
	BIGNUM *one = BN_new();
	BN_dec2bn(&one, "1");
	BN_add(function_Na2, step3_Na2, one);

	// turn function of Na2 into array
	int functionNa2_Length = BN_num_bytes(function_Na2);
	uint8_t function_Na2_Array[functionNa2_Length];
	BN_bn2bin(function_Na2, function_Na2_Array);

	// sizes to go into message
	uint8_t functionNa2_Size[sizeof(int)];
	snprintf(functionNa2_Size, sizeof(int), "%d", functionNa2_Length);
	uint8_t nonceB_Size[sizeof(int)];
	snprintf(nonceB_Size, sizeof(int), "%d", nonceBLength);

	// combine function of Na2 and Nb for encryption
	int step4_tempLength = functionNa2_Length + nonceBLength + (sizeof(int)*2);
	uint8_t step4_tempSize[sizeof(int)];
	snprintf(step4_tempSize, sizeof(int), "%d", step4_tempLength);	

	int step4_plaintextLength = step4_tempLength + sizeof(int);
	uint8_t step4_plaintext[step4_plaintextLength];

	int step4_tempIndex = 0;
	
	// put the size of the combined plaintext in the message
	memcpy(step4_plaintext + step4_tempIndex, step4_tempSize, sizeof(int));
	step4_tempIndex += sizeof(int);

	// put the size of function of Na2 in array	
	memcpy(step4_plaintext + step4_tempIndex, functionNa2_Size, sizeof(int));
	step4_tempIndex += sizeof(int);

	// put the function of Na2 in array
	memcpy(step4_plaintext + step4_tempIndex, function_Na2_Array, functionNa2_Length);
	step4_tempIndex += functionNa2_Length;

	// put the size of Nb in array
	memcpy(step4_plaintext + step4_tempIndex, nonceB_Size, sizeof(int));
	step4_tempIndex += sizeof(int);

	// put Nb into an array
	memcpy(step4_plaintext + step4_tempIndex, nonceB, nonceBLength);

	uint8_t step4_ciphertext[CIPHER_LEN_MAX];
	int step4_ciphertext_Length = encrypt(step4_plaintext, step4_plaintextLength, sessionKey, sessionIV, step4_ciphertext);	

	uint8_t step4_ciphertextSize[sizeof(int)];
	snprintf(step4_ciphertextSize, sizeof(int), "%d", step4_ciphertext_Length);

	int step4_message_Length = step4_ciphertext_Length + sizeof(int); 
	uint8_t step4_message[step4_message_Length];

	int step4_index = 0;

	// put the size of the encryption on the front
	memcpy(step4_message + step4_index, step4_ciphertextSize, sizeof(int));
	step4_index += sizeof(int);

	// put the ciphertext into final message for step 4
	memcpy(step4_message + step4_index, step4_ciphertext, step4_ciphertext_Length);

	fprintf(log, "Wrote to Amal the function of Na2 and Nb encrypted with the session key\n");
    fprintf(log, "Function of Na2: %s\n", BN_bn2hex(function_Na2));
    fprintf(log, "Nb: %s\n", BN_bn2hex(Nb));

	// write the step4 message to the pipe
	write(BtoA_ctrl, step4_message, step4_message_Length);

	/* Step 5 of Protocol */
	fprintf(log, "\n---- Message 5 of Protocol ----\n");	

	uint8_t step5_encrSize[sizeof(int)];
	uint8_t step5_plaintextSize[sizeof(int)];
	uint8_t step5_functionNbSize[sizeof(int)];

	// read the size of the encryption from step 5
	read(AtoB_ctrl, step5_encrSize, sizeof(int));
	int step5_encrLength = atoi(step5_encrSize);

	// read the ciphertext from Amal in step 5
	uint8_t step5_ciphertext[step5_encrLength];
	read(AtoB_ctrl, step5_ciphertext, step5_encrLength);

	// decrypt the message in step 5
	uint8_t step5_plaintext[CIPHER_LEN_MAX];
	int step5_plaintextLength = decrypt(step5_ciphertext, step5_encrLength, sessionKey, sessionIV, step5_plaintext);

	int step5_curIndex = 0;	

	// memcpy the entire length of plaintext
	memcpy(step5_plaintextSize, step5_plaintext + step5_curIndex, sizeof(int));
	step5_curIndex += sizeof(int);

	// memcpy the size of f(Nb)
	memcpy(step5_functionNbSize, step5_plaintext + step5_curIndex, sizeof(int));
	step5_curIndex += sizeof(int);

	// memcpy the f(Nb)
	int step5_functionNbLength = atoi(step5_functionNbSize);
	uint8_t step5_fNbArray[step5_functionNbLength];
	memcpy(step5_fNbArray, step5_plaintext + step5_curIndex, step5_functionNbLength);

	// turn array into BIGNUM
	BIGNUM* step5_fNb = BN_new();
	BN_bin2bn(step5_fNbArray, step5_functionNbLength, step5_fNb);
		 
	BIGNUM *checkFunctionNb = BN_new();
	BN_sub(checkFunctionNb, step5_fNb, one);	

	// check to make sure nonces match after function is applied in reverse
	if (BN_cmp(Nb, checkFunctionNb) != 0)
	{
		fprintf(log, "Nonce received from the Basim does not match Na2, exiting\n");
		exit(-1);
	}

	fprintf(log, "Read the function of Nb from Amal\n");
	fprintf(log, "f(Nb): %s\n", BN_bn2hex(step5_fNb));
	fprintf(log, "Na2 after function applied in opposite way: %s\n" , BN_bn2hex(checkFunctionNb));
	fprintf(log, "\nAMAL HAS BEEN VALIDATED\n");	

	
	/* Read bunny.mp4 file from Amal using session key for decryption */
    decryptFile(AtoB_data, fd_bunny, sessionKey, sessionIV);

	EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;  
    close( AtoB_ctrl ) ;
	close( BtoA_ctrl ) ;
    close( AtoB_data ) ;

    return 0 ;
}

