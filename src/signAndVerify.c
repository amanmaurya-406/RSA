#include "common.h"
#include "sha512.h"
#include "signAndVerify.h"

#define SHA512_DIGEST_LENGTH 64


void RSA_private_encrypt(mpz_t signature, mpz_t hash, mpz_t priv_key, mpz_t mod){  
    mpz_powm(signature, hash, priv_key, mod);   
}

void RSA_public_decrypt(mpz_t decrypted_hash, mpz_t signature, mpz_t pub_key, mpz_t mod){
    mpz_powm(decrypted_hash, signature, pub_key, mod);
}

int sign_message(char *mText, mpz_t sign_priv, mpz_t mod, mpz_t signature){   
    uint8_t *hash = SHA512((uint8_t*)mText, strlen(mText));

    mpz_t hash_m;
    mpz_init(hash_m);
    mpz_import(hash_m, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    
    RSA_private_encrypt(signature, hash_m, sign_priv, mod);

    mpz_clear(hash_m);

    return 1;
}



int verify_message(char *dText, mpz_t signature, mpz_t sign_pub, mpz_t mod){
    uint8_t *hash = SHA512((uint8_t*)dText, strlen(dText));

    mpz_t mText_hash, dText_hash;
    mpz_inits(mText_hash, dText_hash, NULL);
    mpz_import(dText_hash, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    
    RSA_public_decrypt(mText_hash, signature, sign_pub, mod);
    
    int result = mpz_cmp(mText_hash, dText_hash);
    
    mpz_clears(mText_hash, dText_hash, NULL);

    return !result;
}