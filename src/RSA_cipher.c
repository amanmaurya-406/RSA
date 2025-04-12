#include "common.h"
#include "RSA_cipher.h"


int RSA_public_encrypt(char* input_file, mpz_t PU, mpz_t N){
    FILE *f1 = fopen(input_file, "r");
    FILE *f2 = fopen("../data/cipher.txt", "w");
    if(!f1 || !f2){
        printf("ERROR: Opening message file or Creating the encrypted text file.\n");
        return 0;
    }
    
    char c, iMess[5], eMess[1500];                       // iMess -> ASCII_value of one character , eMess -> corresponding encrypted message
    mpz_t encrypted, message;
    mpz_inits(encrypted, message, NULL);

    while((c = getc(f1)) != EOF){
        sprintf(iMess, "%d", c); 
        mpz_set_str(message, iMess, 10);                 // number_string to mpz_t
        mpz_powm(encrypted, message, PU, N);             // encrypted = message ^ PU mod N
        mpz_get_str(eMess, 10, encrypted);
        fputs(strcat(eMess, "\n"), f2);
    }

    mpz_clears(encrypted, message, NULL);
    fclose(f1);
    fclose(f2);
    return 1;
}

int RSA_private_decrypt(char* encrypted_file, mpz_t PR, mpz_t N){
    FILE *f1 = fopen(encrypted_file, "r");
    FILE *f2 = fopen("../data/plain.txt", "w");
    if(!f1 || !f2){
        printf("ERROR: Opening the encrypted file or Creating the plain_text file.\n");
        return 0;
    }

    int num;
    char c, eMess[1500], dMess[4];                       // eMess -> encrypted message , dMess -> corresponding ASCII_value after decryption
    mpz_t encrypted, decrypted;
    mpz_inits(encrypted, decrypted, NULL);

    while(fgets(eMess, sizeof(eMess), f1) != NULL){
        mpz_set_str(encrypted, eMess, 10);
        mpz_powm(decrypted, encrypted, PR, N);           // decrypted = encrypted^PR mod N
        mpz_get_str(dMess, 10, decrypted);
        num = (int)atoi(dMess);                          // Converts a number string to long integer
        c = (char)num;
        putc(c, f2);
    }

    mpz_clears(encrypted, decrypted, NULL);
    fclose(f1);
    fclose(f2);
    return 1;
}