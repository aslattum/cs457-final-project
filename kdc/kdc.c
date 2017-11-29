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

    if( argc < 3 )
    {
        printf("Missing command-line arguments\n") ;
        exit(-1) ;
    }
    int AtoKDC_ctrl = atoi( argv[1] ) ;
    int KDCtoA_ctrl = atoi( argv[2] ) ;

    // Open the log file
    FILE *log = fopen("kdc/logKDC.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is the KDC. Could not create log file\n");
        exit(-1) ;
    }

    fprintf( log , "This is the KDC. Will read from Amal on FD %d.\n", AtoKDC_ctrl);
    fprintf( log , "This is the KDC. Will write back to Amal on FD %d\n\n" , KDCtoA_ctrl);

    /* Step 1 of Protocol */
	
	// sizes represented as uint8_t arrays
	uint8_t totalSizeArray[sizeof(int)];
	uint8_t amalSizeArray[sizeof(int)];
	uint8_t basimSizeArray[sizeof(int)];
	uint8_t nonceSizeArray[sizeof(int)];

	// get the total size of the message
	read(AtoKDC_ctrl, totalSizeArray, sizeof(int));  
	int totalSize = atoi(totalSizeArray);

	// get the size of IDa
	read(AtoKDC_ctrl, amalSizeArray, sizeof(int));
	int amalSize = atoi(amalSizeArray);
	
	// get IDa using the size of IDa
	uint8_t amalArray[amalSize];
	read(AtoKDC_ctrl, amalArray, amalSize);

	// get the size of IDb
    read(AtoKDC_ctrl, basimSizeArray, sizeof(int));
    int basimSize = atoi(basimSizeArray);

	// get IDb using the size of IDb
	uint8_t basimArray[basimSize];
	read(AtoKDC_ctrl, basimArray, basimSize);

	// get the size of the nonce
	read(AtoKDC_ctrl, nonceSizeArray, sizeof(int));
	int nonceSize = atoi(nonceSizeArray);

	// get Na using the size of Na
	uint8_t nonceArray[nonceSize];
	read(AtoKDC_ctrl, nonceArray, nonceSize);
	BIGNUM *Na = BN_new();
	BN_bin2bn(nonceArray, nonceSize, Na);
	
	// check to see if IDa and IDb check out
	if (strncmp(amalArray, "Amal", 5) != 0)
	{
		fprintf(log, "Received incorrect IDa\n");
		exit(-1);
	}
	if (strncmp(basimArray, "Basim", 6) != 0)
	{
		fprintf(log, "Received incorrect IDb\n");
		exit(-1);
	}

	// log out the results in the KDC log
	fprintf(log, "---- Step 1 of Protocol ----\n");
	fprintf(log, "Read IDa, IDb, and Na from Amal\n");
	fprintf(log , "IDa: %s\n", amalArray);
	fprintf(log, "IDb: %s\n", basimArray);
	fprintf(log, "Na: %s\n", BN_bn2hex(Na));

	/* Step 2 of Protocol */
	fprintf(log, "\n---- Step 2 of Protocol ----\n");
	unsigned key_len = 32; // i.e. 256 bits
	unsigned iv_len = 16; // i.e. 128 bits

	// create array for session key, amal and basim keys
	uint8_t sessionKey[EVP_MAX_KEY_LENGTH];
	uint8_t sessionIV[EVP_MAX_IV_LENGTH];
	uint8_t amalKey[EVP_MAX_KEY_LENGTH];
	uint8_t amalIV[EVP_MAX_IV_LENGTH];
	uint8_t basimKey[EVP_MAX_KEY_LENGTH];
	uint8_t basimIV[EVP_MAX_KEY_LENGTH];
	
	// get the amal key and iv
	int fd_amal_key , fd_amal_iv , fd_basim_key , fd_basim_iv;
	fd_amal_key = open("kdc/amal_key.bin" , O_RDONLY ) ; 
 	if (fd_amal_key < 0) {
		fprintf(log, "ERROR OPENING AMAL KEY\n");
	}
	read ( fd_amal_key , amalKey , key_len ) ; 
 	close( fd_amal_key ) ; 
 	fd_amal_iv = open("kdc/amal_iv.bin" , O_RDONLY ) ; 
 	if (fd_amal_iv < 0) {
        fprintf(log, "ERROR OPENING AMAL IV\n");
    }
	read ( fd_amal_iv , amalIV , iv_len ) ; 
 	close( fd_amal_iv ) ; 	

	// get the basim key and iv
    fd_basim_key = open("kdc/basim_key.bin" , O_RDONLY ) ; 
    if (fd_basim_key < 0) {
		fprintf(log, "ERROR OPENING BASIM KEY\n");
	}
	read ( fd_basim_key , basimKey , key_len ) ; 
    close( fd_basim_key ) ; 
    fd_basim_iv = open("kdc/basim_iv.bin" , O_RDONLY ) ; 
   	if (fd_basim_iv < 0) {
        fprintf(log, "ERROR OPENING BASIM IV\n");
    }  
	read ( fd_basim_iv , basimIV , iv_len ) ; 
    close( fd_basim_iv ) ; 

	// create the session key
	RAND_bytes(sessionKey, key_len);
	RAND_bytes(sessionIV, iv_len);

	// combine the session key, iv, and IDa for encryption using basim's key
	int sesKeyLength = sizeof(sessionKey);
	int sesIVLength = sizeof(sessionIV);

	// length is message length
	int plaintextLength = sesKeyLength + sesIVLength + amalSize + (sizeof(int)*3);	     			
	// total includes the int to represent the length
	int plaintextTotal = plaintextLength + sizeof(int);

	uint8_t sesKeySize[sizeof(int)];
	uint8_t sesIVSize[sizeof(int)];
	uint8_t plaintextSize[sizeof(int)];

	// copy sizes into uint8_t arrays so taht you can memcpy them
	snprintf(sesKeySize, sizeof(int), "%d", sesKeyLength);
	snprintf(sesIVSize, sizeof(int), "%d", sesIVLength);
	snprintf(plaintextSize, sizeof(int), "%d", plaintextLength);

	int basimEncrIndex = 0;
	uint8_t innerEncrMessage[plaintextTotal];
	
	memcpy(innerEncrMessage + basimEncrIndex, plaintextSize, sizeof(int));
	basimEncrIndex += sizeof(int);
	memcpy(innerEncrMessage + basimEncrIndex, sesKeySize, sizeof(int));
	basimEncrIndex += sizeof(int);
	memcpy(innerEncrMessage + basimEncrIndex, sessionKey, sizeof(sessionKey));
	basimEncrIndex += sizeof(sessionKey);
	memcpy(innerEncrMessage + basimEncrIndex, sesIVSize, sizeof(int));
	basimEncrIndex += sizeof(int);
	memcpy(innerEncrMessage + basimEncrIndex, sessionIV, sizeof(sessionIV));
	basimEncrIndex += sizeof(sessionIV);
	memcpy(innerEncrMessage + basimEncrIndex, amalSizeArray, sizeof(int));
	basimEncrIndex += sizeof(int);
	memcpy(innerEncrMessage + basimEncrIndex, amalArray, sizeof(amalArray));
	basimEncrIndex += sizeof(amalArray); 
	
	// encrypt the message that is intended for basim
	uint8_t innerCipher[CIPHER_LEN_MAX];
	int innerCipherLength = encrypt(innerEncrMessage, plaintextTotal, basimKey, basimIV, innerCipher);     	
	
	uint8_t innerCipherSize[sizeof(int)];
	snprintf(innerCipherSize, sizeof(int), "%d", innerCipherLength);

	// create rest of the message for step 2
	int tempMsgLength = sesKeyLength + basimSize + nonceSize + innerCipherLength + (sizeof(int)*9);
	int entireMsgLength = tempMsgLength + sizeof(int);
	
	uint8_t entireMsgLengthArray[sizeof(int)];
	snprintf(entireMsgLengthArray, sizeof(int), "%d", entireMsgLength);

	int outerIndex = 0;
	uint8_t entirePlaintext[entireMsgLength];

	// construct the entire step 2 message
	memcpy(entirePlaintext + outerIndex, entireMsgLengthArray, sizeof(int));
	outerIndex += sizeof(int);
	memcpy(entirePlaintext + outerIndex, sesKeySize, sizeof(int));
	outerIndex += sizeof(int);
	memcpy(entirePlaintext + outerIndex, sessionKey, sesKeyLength);
	outerIndex += sesKeyLength;									 
	memcpy(entirePlaintext + outerIndex, sesIVSize, sizeof(int));
	outerIndex += sizeof(int);
	memcpy(entirePlaintext + outerIndex, sessionIV, sesIVLength);
	outerIndex += sesIVLength;
	memcpy(entirePlaintext + outerIndex, basimSizeArray, sizeof(int));
	outerIndex += sizeof(int);
	memcpy(entirePlaintext + outerIndex, basimArray, basimSize);
	outerIndex += basimSize;
    memcpy(entirePlaintext + outerIndex, nonceSizeArray, sizeof(int));
    outerIndex += sizeof(int);
    memcpy(entirePlaintext + outerIndex, nonceArray, nonceSize);
    outerIndex += nonceSize;
	memcpy(entirePlaintext + outerIndex, innerCipherSize, sizeof(int));
	outerIndex += sizeof(int);
	memcpy(entirePlaintext + outerIndex, innerCipher, innerCipherLength);
	outerIndex += innerCipherLength;	 
	
	// encrypt the message that is intended for amal
    uint8_t outerCipher[CIPHER_LEN_MAX];
    int outerCipherLength = encrypt(entirePlaintext, entireMsgLength, amalKey, amalIV, outerCipher);
	
	uint8_t outerCipherSize[sizeof(int)];
    snprintf(outerCipherSize, sizeof(int), "%d", outerCipherLength);

	int totalMsgSize = sizeof(int) + outerCipherLength;
	
	int totalIndex = 0;
	uint8_t step2_message[totalMsgSize];

	memcpy(step2_message + totalIndex, outerCipherSize, sizeof(int));
	totalIndex += sizeof(int);
	memcpy(step2_message + totalIndex, outerCipher, outerCipherLength); 

	fprintf(log, "Sending to amal the encryption of Ks, IDb, and Na as well as the encryption intended for basim\n");
	fprintf(log, "Hexdump of Ks Key:\n");
	BIO_dump_fp (log, (const char *) sessionKey, sesKeyLength);
	fprintf(log, "Hexdump of Ks IV:\n");
	BIO_dump_fp (log, (const char *) sessionIV, sesIVLength);
	fprintf(log, "IDb: %s\n", basimArray);
	fprintf(log, "Na: %s\n", BN_bn2hex(Na));
	fprintf(log, "Ciphertext intended for basim:\n");
	BIO_dump_fp (log, (const char *) innerCipher, innerCipherLength);

	write(KDCtoA_ctrl, step2_message, totalMsgSize);

	EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;
    close(AtoKDC_ctrl);
    close(KDCtoA_ctrl);

    return 0 ;
}

