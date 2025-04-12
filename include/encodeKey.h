#ifndef ENCODE_KEY_H
#define ENCODE_KEY_H

#include <gmp.h>

typedef struct {
    mpz_t n;
    mpz_t e;
    mpz_t d;
    mpz_t p;
    mpz_t q;
    mpz_t dmp1;
    mpz_t dmq1;
    mpz_t iqmp;
} PrivateKey ;

typedef struct {
    mpz_t n;
    mpz_t e;
} PublicKey ;

// WRITING KEYS IN PKCS#1 format following ASN.1 structure
void write_privateKey_der(const char *filename, mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q, mpz_t p_1, mpz_t q_1);
void write_privateKey_pem(const char *filename, mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q, mpz_t p_1, mpz_t q_1);


PrivateKey *load_privateKey(const char *filename);
PublicKey *load_publicBytes(const char *filename);
PublicKey *extract_publicBytes(PrivateKey *privateKey);
void free_privateKey(PrivateKey *privateKey);
void free_publicKey(PublicKey *publicKey);


#endif