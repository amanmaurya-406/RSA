#include <time.h>
#include "common.h"
#include "RSA_generateKey.h"
#include "encodeKey.h"


static void generate_prime(mpz_t prime, unsigned int bit_size, gmp_randstate_t state){
    mpz_t random_num;
    mpz_init(random_num);

    mpz_urandomb(random_num, state, bit_size);
    mpz_setbit(random_num, bit_size - 1);

    mpz_nextprime(prime, random_num);

    mpz_clear(random_num);
}

int generate_RSA_keys(const char *filename){
    mpz_t n, e, d, p, q, p_1, q_1, phi, gcd;
    mpz_inits(n, e, d, p, q, p_1, q_1, phi, gcd, NULL);
    
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    unsigned long seed = time(NULL);
    gmp_randseed_ui(state, seed);

    unsigned int bit_size;
    printf("Enter the Size (<= 4096) of the key to be generated: ");
    scanf("%d", &bit_size);

    generate_prime(p, bit_size / 2, state);      // Generate prime number 1
    generate_prime(q, bit_size / 2, state);      // Generate prime number 2

    mpz_mul(n, p, q);                                   // n = p * q
    mpz_sub_ui(p_1, p, 1);                              // p_1 = p - 1
    mpz_sub_ui(q_1, q, 1);                              // q_1 = q - 1
    mpz_mul(phi, p_1, q_1);                             // phi = p_1 * q_1


    /* // Generate random Public Key (e)
    do{
        mpz_urandomb(e, state, 16);          // Generate a random 16-bit number for e
        mpz_gcd(gcd, e, phi);                // Ensure gcd(e, phi) = 1
    }while(mpz_cmp_ui(e, 1) <= 0 || mpz_cmp(e, phi) >= 0 || mpz_cmp_ui(gcd, 1) != 0); */
    mpz_set_str(e, "65537", 10);
    
    // Generate Private Key (d)
    if(mpz_invert(d, e, phi) != 0){         // d * e mod phi = 1
        write_privateKey_pem(filename, n, e, d, p, q, p_1, q_1);
    }
    else{
        gmp_printf("No modular inverse found. Public key %Zd and phi %Zd are not coprime.\n", e, phi);
    }
    
    mpz_clears(n, e, d, p, q, p_1, q_1, phi, gcd, NULL);
    gmp_randclear(state);

    return (mpz_invert(d, e, phi) != 0);
}