/*----------------------------------------------------------------------------
Final-Project: Needham-Schroeder Protocol

FILE:   amal.c

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

    if( argc < 6 )
    {
        printf("Missing command-line arguments\n") ;
        exit(-1) ;
    }
    int AtoB_ctrl   = atoi( argv[1] ) ;
    int AtoB_data   = atoi( argv[2] ) ;
    int AtoKDC_ctrl = atoi( argv[3] ) ;
    int KDCtoA_ctrl = atoi( argv[4] ) ;
    int BtoA_ctrl   = atoi( argv[5] ) ;

    // Open the log file
    FILE *log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }

    fprintf( log , "This is Amal. Will send to KDC on FD %d\n", AtoKDC_ctrl);
    fprintf( log , "This is Amal. Will read from the KDC on FD %d\n", KDCtoA_ctrl);
    fprintf( log , "This is Amal. Will write to Basim on FD %d\n", AtoB_ctrl);
    fprintf( log , "This is Amal. Will read from Basim on FD %d\n", BtoA_ctrl);
    fprintf( log , "This is Amal. Will write the bunny file to Basim on FD %d\n\n",  AtoB_data);

    // Open the file that we will send
    int fd_bunny = open("amal/bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
    if( fd_bunny == -1 )
    {
        fprintf( stderr , "This is Amal. Could not open input file\n");
        exit(-1) ;
    }

    /* Step One of Protocol */
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *Na = BN_new();
    BIGNUM *range = BN_new();

    // craete two and 64 random nums to do 2^64 range for random num
    BIGNUM *two = BN_new();
    BIGNUM *sixty_four = BN_new();
    BN_dec2bn(&two, "2");
    BN_dec2bn(&sixty_four, "64");

    // create the range for the random num
    BN_exp(range, two, sixty_four, ctx);

    // create the random nonce Na
    BN_rand_range(Na, range);

	uint8_t IDa[] = "Amal";
    uint8_t IDb[] = "Basim";
	int amalLength = 5;
	int basimLength = 6;
	int nonceLength = BN_num_bytes(Na);
    uint8_t nonce[nonceLength];
	
	// transform big num into binary
	BN_bn2bin(Na, nonce);

	// totalLength is the message length
	int totalLength = amalLength + basimLength + nonceLength + (sizeof(int)*3);
	// writeSize is the message length plus the size of the length of the message
	int writeSize = totalLength + sizeof(int);

	uint8_t amalSize[sizeof(int)];
	uint8_t basimSize[sizeof(int)];
	uint8_t nonceSize[sizeof(int)]; 
	uint8_t totalSize[sizeof(int)];

	// copy sizes into uint8_t arrays so that you can memcpy them
	snprintf(amalSize, sizeof(int), "%d", amalLength);	 
	snprintf(basimSize, sizeof(int), "%d", basimLength);
	snprintf(nonceSize, sizeof(int), "%d", nonceLength);
	snprintf(totalSize, sizeof(int), "%d", totalLength);

	// current index for memcpy
	int curIndex = 0;
	uint8_t step1_message[writeSize];

	// memcpy the sizes and information into one giant uint8_t array	
	memcpy(step1_message + curIndex, totalSize, sizeof(int));
	curIndex += sizeof(totalSize);
	memcpy(step1_message + curIndex, amalSize, sizeof(int));
	curIndex += sizeof(amalSize);
	memcpy(step1_message + curIndex, IDa, amalLength);
    curIndex += sizeof(IDa);
	memcpy(step1_message + curIndex, basimSize, sizeof(int));
    curIndex += sizeof(basimSize);
	memcpy(step1_message + curIndex, IDb, basimLength);
    curIndex += sizeof(IDb);
	memcpy(step1_message + curIndex, nonceSize, sizeof(int));
    curIndex += sizeof(nonceSize);
	memcpy(step1_message + curIndex, nonce, nonceLength);
    curIndex += sizeof(nonce);

	// write the step 1 message to the KDC on the A to KDC control pipe		
    int KDC_write = write(AtoKDC_ctrl, step1_message, writeSize);
    if (KDC_write < writeSize) {
        fprintf( log , "Write to the KDC failed" );
    } else {
		fprintf( log , "---- Message  1 of Protocol ----\n");
        fprintf( log , "Wrote the IDa, IDb, and Na to the KDC\n");
        fprintf( log , "IDa: %s\n", IDa);
        fprintf( log , "IDb: %s\n", IDb);
        fprintf( log , "Na: %s\n", BN_bn2hex(Na));
	}

	/* Step 2 of Protocol */
	fprintf(log, "\n---- Message 2 of Protocol ----\n");
	
	unsigned key_len = 32; // i.e. 256 bits
    unsigned iv_len = 16; // i.e. 128 bits

	// arrays for the key and iv
	uint8_t amalKey[EVP_MAX_KEY_LENGTH];
    uint8_t amalIV[EVP_MAX_IV_LENGTH];	
	
	// get the amal key and iv
    int fd_amal_key , fd_amal_iv;
    fd_amal_key = open("amal/amal_key.bin" , O_RDONLY ) ; 
    if (fd_amal_key < 0) {
        fprintf(log, "ERROR OPENING AMAL KEY\n");
    }   
    read ( fd_amal_key , amalKey , key_len ) ; 
    close( fd_amal_key ) ; 
    fd_amal_iv = open("amal/amal_iv.bin" , O_RDONLY ) ; 
    if (fd_amal_iv < 0) {
        fprintf(log, "ERROR OPENING AMAL IV\n");
    }   
    read ( fd_amal_iv , amalIV , iv_len ) ; 
    close( fd_amal_iv ) ;	

	// sizes represented as uint8_t arrays
    uint8_t outerEncrArraySize[sizeof(int)];
	uint8_t entirePlaintextSize[sizeof(int)];
	uint8_t step2_KsKey_Size[sizeof(int)];
	uint8_t step2_KsIV_Size[sizeof(int)];
	uint8_t step2_IDb_Size[sizeof(int)];
	uint8_t step2_Na_Size[sizeof(int)];
	uint8_t step2_innerEncrSize[sizeof(int)];

    // get the total size of the message
    read(KDCtoA_ctrl, outerEncrArraySize, sizeof(int));  
    int outerEncrLength = atoi(outerEncrArraySize);

	// decrypt the outer message
    uint8_t step2_outerCipher[outerEncrLength];
	uint8_t step2_outerPlaintext[CIPHER_LEN_MAX];
	read(KDCtoA_ctrl, step2_outerCipher, outerEncrLength);
	int outerNumDecrypted = decrypt( step2_outerCipher, outerEncrLength, amalKey, amalIV, step2_outerPlaintext);
	
	int outerIndex = 0;

    // deconstruct the entire step 2 message
    memcpy(entirePlaintextSize, step2_outerPlaintext + outerIndex, sizeof(int));
    outerIndex += sizeof(int);
   	
	// get the KS key size 
	memcpy(step2_KsKey_Size, step2_outerPlaintext + outerIndex, sizeof(int));
    outerIndex += sizeof(int);

	// use the KS key size to read the KS key into a uint8_t array
	int step2_KsKey_Length = atoi(step2_KsKey_Size);
	uint8_t step2_KsKey[step2_KsKey_Length];
	memcpy(step2_KsKey, step2_outerPlaintext + outerIndex, step2_KsKey_Length);
    outerIndex += step2_KsKey_Length;

	// get the KS IV size	    
    memcpy(step2_KsIV_Size, step2_outerPlaintext + outerIndex, sizeof(int));
    outerIndex += sizeof(int);

	// use the KS IV size to read the KS iv into a uint8_t array
	int step2_KsIV_Length = atoi(step2_KsIV_Size);
	uint8_t step2_KsIV[step2_KsIV_Length];
    memcpy(step2_KsIV, step2_outerPlaintext + outerIndex, step2_KsIV_Length);
    outerIndex += step2_KsIV_Length;

	// get the IDb size
    memcpy(step2_IDb_Size, step2_outerPlaintext + outerIndex, sizeof(int));
    outerIndex += sizeof(int);
	
	// get the IDb based on IDb size
   	int step2_IDb_Length = atoi(step2_IDb_Size);
	uint8_t step2_IDb[step2_IDb_Length];
	memcpy(step2_IDb, step2_outerPlaintext + outerIndex, step2_IDb_Length);
    outerIndex += step2_IDb_Length;

	// get the Na size
    memcpy(step2_Na_Size, step2_outerPlaintext + outerIndex, sizeof(int));
    outerIndex += sizeof(int);

	// get the Na from the Na size
	int step2_Na_Length = atoi(step2_Na_Size);
	uint8_t step2_Na[step2_Na_Length];
    memcpy(step2_Na, step2_outerPlaintext + outerIndex, step2_Na_Length);
	outerIndex += step2_Na_Length;

	// check that the nonce you sent to the KDC is correctly returned
	BIGNUM* step2_Na_BN = BN_new();
    BN_bin2bn(step2_Na, step2_Na_Length, step2_Na_BN);
	if (BN_cmp(Na, step2_Na_BN) != 0)
	{
		fprintf(log, "Nonce received from the KDC does not match, exiting\n");
		exit(-1);
	}

	// get the ciphertext size intended for basim
    memcpy(step2_innerEncrSize, step2_outerPlaintext + outerIndex, sizeof(int));
    outerIndex += sizeof(int);

	// get the ciphertext sent to amal intended for basim using the size from above
    int step2_innerEncr_Length = atoi(step2_innerEncrSize);
	uint8_t step2_innerEncr[step2_innerEncr_Length];
	memcpy(step2_innerEncr, step2_outerPlaintext + outerIndex, step2_innerEncr_Length); 

	fprintf(log, "Reading from the KDC, the encryption of Ks, IDb, and Na as well as the encryption intended for basim\n");
    fprintf(log, "Hexdump of Ks Key:\n");
    BIO_dump_fp (log, (const char *) step2_KsKey, key_len);
    fprintf(log, "Hexdump of Ks IV:\n");
    BIO_dump_fp (log, (const char *) step2_KsIV, step2_KsIV_Length);
    fprintf(log, "IDb: %s\n", step2_IDb);
    fprintf(log, "Nonce's match, Na: %s\n", BN_bn2hex(step2_Na_BN));
    fprintf(log, "Ciphertext intended for basim:\n");
    BIO_dump_fp (log, (const char *) step2_innerEncr, step2_innerEncr_Length);

	/* Step 3 of Protocol */
	fprintf(log, "\n---- Message 3 of Protocol ----\n");

	// create a new nonce for transmission to basim from amal
	BIGNUM* Na2 = BN_new();
	BN_rand_range(Na2, range);	

	// get the size of the nonce and transform it into a uint8_t array for transmission over pipe	
	int nonce2Length = BN_num_bytes(Na2);
	uint8_t nonce2Size[sizeof(int)];
	snprintf(nonce2Size, sizeof(int), "%d", nonce2Length);  
 
	// transform big num into binary for transmission over pipe 
	uint8_t nonce2[nonce2Length];
    BN_bn2bin(Na2, nonce2);	

	int step3_tempLength = step2_innerEncr_Length + nonce2Length + (sizeof(int)*2);
	uint8_t step3_preTotal[step3_tempLength];

	int step3_index = 0;

	// send the size of the encryption
	memcpy(step3_preTotal + step3_index, step2_innerEncrSize, sizeof(int));
    step3_index += sizeof(int);

	// send the encryption itself
	memcpy(step3_preTotal + step3_index, step2_innerEncr, step2_innerEncr_Length);
	step3_index += step2_innerEncr_Length;

	// send the size of the nonce
	memcpy(step3_preTotal + step3_index, nonce2Size, sizeof(int));
	step3_index += sizeof(int);

	// send the nonce itself
	memcpy(step3_preTotal + step3_index, nonce2, nonce2Length);
	step3_index += nonce2Length; 
  	
	// construct final step 3 message with size out front
	int step3_totalLength = step3_tempLength + sizeof(int);
	uint8_t step3_totalSize[sizeof(int)];
	snprintf(step3_totalSize, sizeof(int), "%d", step3_totalLength);

	uint8_t step3_message[step3_totalLength];
	int step3_final_index = 0;

	memcpy(step3_message + step3_final_index, step3_totalSize, sizeof(int));
	step3_final_index += sizeof(int);
	
	memcpy(step3_message + step3_final_index, step3_preTotal, step3_tempLength);			

	fprintf( log , "Wrote to basim the ciphertext intended for basim and a fresh Na2\n");
	fprintf(log, "Ciphertext intended for basim:\n");
    BIO_dump_fp (log, (const char *) step2_innerEncr, step2_innerEncr_Length);
	fprintf( log , "Na2: %s\n", BN_bn2hex(Na2));

	// write step3 message to basim
	write(AtoB_ctrl, step3_message, step3_totalLength);	

	/* Step 4 of Protocol */
	fprintf(log, "\n---- Message 4 of Protocol ----\n");
	
	uint8_t step4_encrSize[sizeof(int)];
	uint8_t step4_plaintextSize[sizeof(int)];
	uint8_t step4_functionNa2Size[sizeof(int)];
	uint8_t step4_NbSize[sizeof(int)];

	// read the size of the encryption in step 4
	read(BtoA_ctrl, step4_encrSize, sizeof(int));
	int step4_ciphertextLength = atoi(step4_encrSize);

	// read the ciphertext in sent from basim
	uint8_t step4_ciphertext[step4_ciphertextLength];
	read(BtoA_ctrl, step4_ciphertext, step4_ciphertextLength);

	uint8_t step4_plaintext[CIPHER_LEN_MAX];
	int step4_plaintextLength = decrypt(step4_ciphertext, step4_ciphertextLength, step2_KsKey, step2_KsIV, step4_plaintext);

	int step4_read_index = 0;

	// read in the size of the plaintext
	memcpy(step4_plaintextSize, step4_plaintext + step4_read_index, sizeof(int));
	step4_read_index += sizeof(int);	 

	// read in the size of the function of Na2 sent to basim in step 3
	memcpy(step4_functionNa2Size, step4_plaintext + step4_read_index, sizeof(int));
	step4_read_index += sizeof(int);

	// read in the function of Na2
	int functionNa2Length = atoi(step4_functionNa2Size);
	uint8_t functionNa2[functionNa2Length];
	memcpy(functionNa2, step4_plaintext + step4_read_index, functionNa2Length);
	step4_read_index += functionNa2Length;

	// check that the function of the nonce checks out to validate basim
	BIGNUM* step4_functionNa2_BN = BN_new();
    BN_bin2bn(functionNa2, functionNa2Length, step4_functionNa2_BN);
	BIGNUM *one = BN_new();
	BN_dec2bn(&one, "1");
	BIGNUM *checkFunctionNa2 = BN_new();
	BN_sub(checkFunctionNa2, step4_functionNa2_BN, one);	

	// check to make sure nonces match after function is applied in reverse
	if (BN_cmp(Na2, checkFunctionNa2) != 0)
	{
		fprintf(log, "Nonce received from the Basim does not match Na2, exiting\n");
		exit(-1);
	}

	// read in the size of Nb
	memcpy(step4_NbSize, step4_plaintext + step4_read_index, sizeof(int));
	step4_read_index += sizeof(int);

	// read in Nb
	int step4_NbLength = atoi(step4_NbSize);
	uint8_t step4_Nb[step4_NbLength];
	memcpy(step4_Nb, step4_plaintext + step4_read_index, step4_NbLength); 

	BIGNUM* Nb = BN_new();
	BN_bin2bn(step4_Nb, step4_NbLength, Nb);

	//log out important information
	fprintf(log, "Read function of Na2 and Nb from Basim\n");	
	fprintf(log, "f(Na2): %s\n", BN_bn2hex(step4_functionNa2_BN));
	fprintf(log, "Na2 after function applied in opposite way: %s\n", BN_bn2hex(checkFunctionNa2));
	fprintf(log, "Nb: %s\n", BN_bn2hex(Nb)); 
	fprintf(log, "\nBASIM HAS BEEN VALIDATED\n");


	/* Step 5 of Protocol */
	fprintf(log, "\n---- Message 5 of Protocol ----\n");

	// function of Nb to send back to basim
	BIGNUM* functionNb_BN = BN_new();
	BN_add(functionNb_BN, Nb, one);

	// store function Nb in uint8_t array	
	int functionNbLength = BN_num_bytes(functionNb_BN);
	uint8_t functionNbArray[functionNbLength];
	BN_bn2bin(functionNb_BN, functionNbArray);

	// store size of function Nb in array
	uint8_t functionNbSize[sizeof(int)];
	snprintf(functionNbSize, sizeof(int), "%d", functionNbLength);

	// total size to be encrypted
	int step5_plaintextLength = functionNbLength + sizeof(int);
    uint8_t step5_plaintextTempSize[sizeof(int)];
	snprintf(step5_plaintextTempSize, sizeof(int), "%d", step5_plaintextLength);
    int step5_totalPlaintextLength = step5_plaintextLength + sizeof(int);
	uint8_t step5_plaintext[step5_totalPlaintextLength];

	int step5_inner_index = 0;

	// put total size into array
	memcpy(step5_plaintext + step5_inner_index, step5_plaintextTempSize, sizeof(int));
	step5_inner_index += sizeof(int);	

	// put Nb size in plaintext array
	memcpy(step5_plaintext + step5_inner_index, functionNbSize, sizeof(int));
	step5_inner_index += sizeof(int);

	// put Nb in plaintext array
	memcpy(step5_plaintext + step5_inner_index, functionNbArray, functionNbLength);

	// encrypt the function of the Nb
	uint8_t step5_ciphertext[CIPHER_LEN_MAX];
	int step5_ciphertextLength = encrypt(step5_plaintext, step5_totalPlaintextLength, step2_KsKey, step2_KsIV, step5_ciphertext);

	// store size of cipher text as an array
	uint8_t step5_ciphertextSize[sizeof(int)];
	snprintf(step5_ciphertextSize, sizeof(int), "%d", step5_ciphertextLength);

	int step5_messageLength = step5_ciphertextLength + sizeof(int);
	uint8_t step5_message[step5_messageLength];

	int step5_finalIndex = 0;

	// store size of the ciphertext in final step 5 message array
	memcpy(step5_message + step5_finalIndex, step5_ciphertextSize, sizeof(int));
	step5_finalIndex += sizeof(int);

	// store ciphertext in final step 5 message array
	memcpy(step5_message + step5_finalIndex, step5_ciphertext, step5_ciphertextLength); 

	fprintf(log, "Wrote the function of Nb back to Basim encrypted with the session key\n");
	fprintf(log, "f(Nb): %s\n", BN_bn2hex(functionNb_BN));

	// write the step5 message
	write(AtoB_ctrl, step5_message, step5_messageLength);


	/* Transmit bunny.mp4 file to basim using session key for encryption */
	encryptFile(fd_bunny, AtoB_data, step2_KsKey, step2_KsIV);
	
    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;
    close(AtoB_ctrl);
    close(AtoB_data);
    close(AtoKDC_ctrl);
    close(KDCtoA_ctrl);
    close(BtoA_ctrl);
    close(fd_bunny);

    return 0 ;
}

