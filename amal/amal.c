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

    /* Step One of Protocol */
    char *IDa = "Amal";
    int sizeIDa = 4;
    char *IDb = "Basim";
    int sizeIDb = 5;

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

    uint8_t IDa_array[sizeof(sizeIDa) + sizeIDa];
    uint8_t IDb_array[sizeof(sizeIDb) + sizeIDb];
    uint8_t Na_array[sizeof(BN_num_bytes(Na)) + BN_num_bytes(Na)];

    uint8_t temp_size = sizeof(IDa_array) + sizeof(IDb_array) + sizeof(Na_array);
    uint8_t step1_total_size = sizeof(temp_size) + temp_size;

    uint8_t step1_array[step1_total_size];

    int KDC_write1 = write(AtoKDC_ctrl, IDa, sizeof(IDa));
    int KDC_write2 = write(AtoKDC_ctrl, IDb, sizeof(IDb));
    int KDC_write3 = BN_write_fd(Na, AtoKDC_ctrl);
    if (KDC_write1 < sizeof(IDa) || KDC_write2 < sizeof(IDb) || KDC_write3 != 1) {
        fprintf( log , "Write to the KDC failed" );
    } else {
        fprintf( log , "Wrote the IDa, IDb, and Na to the KDC\n");
        fprintf( log , "IDa: %s\n", IDa);
        fprintf( log , "IDb: %s\n", IDb);
        fprintf( log , "Na: %s\n", BN_bn2hex(Na));
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

