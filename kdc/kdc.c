/*----------------------------------------------------------------------------
Final-Project: Needham-Schroeder Protocol

FILE:   amal.c

Written By: 
     1- Adam Slattum    
     
Submitted on: 12/3/17 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"
int main ( int argc , char * argv[] )
{

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
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
	fprintf( log , "This is the KDC. Will write back to Amal on FD %d\n" , KDCtoA_ctrl);

    EVP_cleanup();
    ERR_free_strings();
    
    fclose( log ) ;
    close(AtoKDC_ctrl);
    close(KDCtoA_ctrl);

    return 0 ;
}

