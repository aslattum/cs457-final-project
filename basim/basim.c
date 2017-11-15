/*----------------------------------------------------------------------------
Final-Project: Needham-Schroeder Protocol 

FILE:   basim.c

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

    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;  
    close( AtoB_ctrl ) ;
	close( BtoA_ctrl ) ;
    close( AtoB_data ) ;

    return 0 ;
}

