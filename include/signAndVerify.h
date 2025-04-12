#ifndef SIGN_AND_VERIFY_H
#define SIGN_AND_VERIFY_H

#include <stdint.h>

int sign_message(char *mText, mpz_t sign_priv, mpz_t N, mpz_t signature);
int verify_message(char *dText, mpz_t signature, mpz_t sign_pub, mpz_t N);

#endif