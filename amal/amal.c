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
	fprintf( log , "This is Amal. Will write the bunny file to Basim on FD %d\n",  AtoB_data);

    // Open the file that we will send
    int fd_bunny = open("amal/bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
    if( fd_bunny == -1 )
    {
        fprintf( stderr , "This is Amal. Could not open input file\n");
        exit(-1) ;
    }

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

