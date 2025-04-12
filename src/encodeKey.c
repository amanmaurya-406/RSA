#include <math.h>
#include "common.h"
#include "asn1.h"
#include "encodeKey.h"

#include <openssl/evp.h>

static void write_pem(const char *filename, const char *header, const char *base64_data){
    FILE *file = fopen(filename, "w");
    if(!file){
        perror("Failed to open file");
        return;
    }
    
    fprintf(file, "-----BEGIN %s-----\n", header);

    int len = strlen(base64_data);
    for (int i = 0; i < len; i += 64) {
        fprintf(file, "%.64s\n", base64_data + i);
    }

    fprintf(file, "-----END %s-----", header); 
    fclose(file);
}

static char* read_pem(const char *filename){
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    unsigned char buffer[65];
    char *base64_data = NULL;
    size_t current_length = 0;

    while(fgets((char *)buffer, sizeof(buffer), file)){
        // Skip header and footer lines
        if(strstr((char *)buffer, "-----") != NULL){
            continue;
        }

        // Remove the trailing newline
        size_t buffer_len = strlen((char *)buffer);
        if(buffer[buffer_len - 1] == '\n'){
            buffer[buffer_len - 1] = '\0';
            buffer_len -= 1;
        }

        // Reallocate memory for concatenating the new line
        base64_data = realloc(base64_data, current_length + buffer_len + 1);
        if(!base64_data){
            perror("Failed to allocate memory");
            fclose(file);
            return NULL;
        }

        strcpy((char *)base64_data + current_length, (char *)buffer);
        current_length += buffer_len;
    }

    fclose(file);

    return base64_data;
}

static char* base64_encode(const unsigned char* input, int input_length){
    int encoded_length = 4 * ceil((input_length + 2)/ 3.0);

    char* encoded = malloc(encoded_length + 1);
    if(!encoded){
        perror("Error allocating memory.\n");
        return NULL;
    }

    int len = EVP_EncodeBlock((unsigned char*)encoded, input, input_length);
    encoded[len] = '\0';
    return encoded;
}

static char* base64_decode(const char* input){
    int input_length = strlen(input);
    int decoded_length = 3 * input_length / 4;

    char* decoded = malloc(decoded_length + 1);
    if(!decoded){
        return NULL;
    }

    EVP_DecodeBlock((unsigned char*)decoded, (const unsigned char*)input, input_length);
    return decoded;
}



static uint8_t *encode_privateKey_der(size_t *countp, mpz_t n, mpz_t e, 
    mpz_t d, mpz_t p, mpz_t q, mpz_t p_1, mpz_t q_1){

    uint8_t version_s[] = { 0x02, 0x01, 0x00 };     // Serilaizing version
    size_t version_size = sizeof(version_s);

    size_t n_size, e_size, d_size, p_size, q_size, dmp1_size, dmq1_size, iqmp_size;

    mpz_t dmp1, dmq1, iqmp;
    mpz_inits(dmp1, dmq1, iqmp, NULL);

    mpz_mod(dmp1, d, p_1);
    mpz_mod(dmq1, d, q_1);
    mpz_invert(iqmp, p, q);

    uint8_t *n_s = serialize_mpz(&n_size, n); 
    uint8_t *e_s = serialize_mpz(&e_size, e);
    uint8_t *d_s = serialize_mpz(&d_size, d);
    uint8_t *p_s = serialize_mpz(&p_size, p);
    uint8_t *q_s = serialize_mpz(&q_size, q);
    uint8_t *dmp1_s = serialize_mpz(&dmp1_size, dmp1);
    uint8_t *dmq1_s = serialize_mpz(&dmq1_size, dmq1);
    uint8_t *iqmp_s = serialize_mpz(&iqmp_size, iqmp);

    size_t total_size = version_size + n_size + e_size + d_size + 
        p_size + q_size + dmp1_size + dmq1_size + iqmp_size;

    uint8_t *total_s = (uint8_t *)malloc(total_size);
    if(!total_s){
        perror("Memory allocation failed\n");
        *countp = 0;
        return NULL;
    }

    int index = 0;

    #define COLLECT_INDIVIDUAL(val_s, val_size)     \
        memcpy(total_s + index, val_s, val_size);       \
        index += val_size;

        COLLECT_INDIVIDUAL(version_s, version_size);
        COLLECT_INDIVIDUAL(n_s, n_size);
        COLLECT_INDIVIDUAL(e_s, e_size);
        COLLECT_INDIVIDUAL(d_s, d_size);
        COLLECT_INDIVIDUAL(p_s, p_size);
        COLLECT_INDIVIDUAL(q_s, q_size);
        COLLECT_INDIVIDUAL(dmp1_s, dmp1_size);
        COLLECT_INDIVIDUAL(dmq1_s, dmq1_size);
        COLLECT_INDIVIDUAL(iqmp_s, iqmp_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(countp, total_size, total_s);

    free(n_s);
    free(e_s);
    free(d_s);
    free(p_s);
    free(q_s);
    free(dmp1_s);
    free(dmq1_s);
    free(iqmp_s);
    free(total_s);
    mpz_clears(dmp1, dmq1, iqmp, NULL);

    return buffer;
    }

void write_privateKey_der(const char *filename, mpz_t n, mpz_t e, 
    mpz_t d, mpz_t p, mpz_t q, mpz_t p_1, mpz_t q_1){

    size_t der_size;
    uint8_t *der = encode_privateKey_der(&der_size, n, e, d, p, q, p_1, q_1);
    if(!der){ return; }

    FILE *fptr = fopen(filename, "wb");
    if(!fptr){
        perror("Error opening file\n");
        return;
    }

    size_t bytesWritten = fwrite(der, 1, der_size, fptr);
    if(bytesWritten != der_size){
        perror("Full data is not written");
    }

    free(der);
    fclose(fptr);
}

void write_privateKey_pem(const char *filename, mpz_t n, mpz_t e, 
    mpz_t d, mpz_t p, mpz_t q, mpz_t p_1, mpz_t q_1){

    size_t der_size;
    uint8_t *der = encode_privateKey_der(&der_size, n, e, d, p, q, p_1, q_1);
    if(!der){ return; }

    uint8_t *b64 = base64_encode(der, der_size);
    if(!b64){ return; }

    write_pem(filename, "RSA PRIVATE KEY", b64);

    free(der);
    free(b64);
}


/**
* @brief Loads a private key from a file.
* 
* This function reads a private key from the specified file and returns a pointer
* to a dynamically allocated PrivateKey structure containing the parsed key data.
* 
* @param filename The path to the file containing the private key (in PEM format).
* @return PrivateKey* to the loaded PrivateKey structure on success, Must be freed after use.
* or NULL on failure (e.g., file not found or invalid format).
*/
PrivateKey *load_privateKey(const char *filename){

    char *b64 = read_pem(filename);
    if(!b64){ return NULL; }

    char *der = base64_decode(b64);
    free(b64);
    if(!der){ return NULL; };

    int idx = 0;
    /* printf("Sequence tag = [0x%02x]\n", */ idx++;
    read_asn1_length(der, &idx);

    int version;
    idx += deserialize_integer(&version, der + idx);

    PrivateKey *privateKey = (PrivateKey *)malloc(sizeof(PrivateKey));
    if(!privateKey){
        perror("Memory allocation failed");
        return NULL;
    }

    mpz_inits(privateKey->n, privateKey->e, privateKey->d, 
            privateKey->p, privateKey->q, privateKey->dmp1, 
            privateKey->dmq1, privateKey->iqmp, NULL);

    idx += deserialize_mpz(privateKey->n, der + idx);
    idx += deserialize_mpz(privateKey->e, der + idx);
    idx += deserialize_mpz(privateKey->d, der + idx);
    idx += deserialize_mpz(privateKey->p, der + idx);
    idx += deserialize_mpz(privateKey->q, der + idx);
    idx += deserialize_mpz(privateKey->dmp1, der + idx);
    idx += deserialize_mpz(privateKey->dmq1, der + idx);
    idx += deserialize_mpz(privateKey->iqmp, der + idx);

    free(der);
    return privateKey;
}

/**
 * @brief Extarcts public key from private key.
 * 
 * @param filename The path to the file containing the private key (in PEM format).
 * @return PublicKey* on success, Must be freed after use.
 * or NULL on failure (e.g., file not found or invalid format).
 */
PublicKey *load_publicBytes(const char *filename){
    char *b64 = read_pem(filename);
    if(!b64){ return NULL; }

    char *der = base64_decode(b64);
    free(b64);
    if(!der){ return NULL; };

    int idx = 0;
    /* printf("Sequence tag = [0x%02x]\n", */ idx++;
    read_asn1_length(der, &idx);

    int version;
    idx += deserialize_integer(&version, der + idx);

    PublicKey *publicKey = (PublicKey *)malloc(sizeof(PublicKey));
    if(!publicKey){
        perror("Memory allocation failed");
        return NULL;
    }

    mpz_inits(publicKey->n, publicKey->e, NULL);

    idx += deserialize_mpz(publicKey->n, der + idx);
    idx += deserialize_mpz(publicKey->e, der + idx);

    free(der);
    return publicKey;
}

void free_privateKey(PrivateKey *privateKey){
    mpz_clears(privateKey->n, privateKey->e, privateKey->d, NULL);
    mpz_clears(privateKey->p, privateKey->q, privateKey->dmp1, NULL);
    mpz_clears(privateKey->dmq1, privateKey->iqmp, NULL);

    free(privateKey);
}

/**
* @brief Extracts a Public key from a Private key.
* 
* @param privateKey PrivateKey structure.
* @return PublicKey* to the extracted PublicKey structure on success, Must be freed after use.
* or NULL on failure (e.g., file not found or invalid format).
*/
PublicKey *extract_publicBytes(PrivateKey *privateKey){

    PublicKey *publicKey = (PublicKey *)malloc(sizeof(PublicKey));
    if(!publicKey){
        perror("Memory allocation failed");
        return NULL;
    }

    mpz_inits(publicKey->n, publicKey->e, NULL);

    mpz_set(publicKey->n, privateKey->n);
    mpz_set(publicKey->e, privateKey->e);

    return publicKey;
}

void free_publicKey(PublicKey *publicKey){
    mpz_clears(publicKey->n, publicKey->e, NULL);

    free(publicKey);
}


