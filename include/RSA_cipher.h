#ifndef RSA_CIPHER_H
#define RSA_CIPHER_H

int RSA_public_encrypt(char* input_file,mpz_t PU, mpz_t N);
int RSA_private_decrypt(char* encrypted_file, mpz_t PR, mpz_t N);

#endif