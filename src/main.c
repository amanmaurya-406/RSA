#include "common.h"
#include "declarations.h"


void display(){
    const char* options[] = {
        "\n[G] Generate Key Pair",
        "[E] Encrypt Message",
        "[D] Decrypt Message",
        "[S] Sign Message",
        "[V] Verify Signature",
        "[X] Exit"
    };
    size_t num_options = sizeof(options) / sizeof(options[0]);

    for (size_t i = 0; i < num_options; i++) {
        printf("%s\n", options[i]);
    }
}

int main(){
    mpz_t signature;
    mpz_init(signature);
    
    char input_file[20], encrypted_file[20], full_path[100];
    char choice;
    
    display();
    do{
        printf("\nChoose an action:  ");
        scanf(" %c", &choice);
        switch(choice){
            case 'G': case 'g':   // Generating Keys
            {   
                if(generate_RSA_keys(DATA_DIR "/receiver_pKey.pem")){  /* Message Receiver's rsa key */
                    printf("Key generated successfully. stored as '%s'.\n", "receiver_pKey.pem");
                }
                else{
                    printf("Key generation failed.\n");
                }
                break;
            }

            case 'E': case 'e':   // Encrypting Message
            {
                strcpy(full_path, DATA_DIR), strcat(full_path, "/receiver_pKey.pem");
                PublicKey *publicKey = load_publicBytes(full_path);
                
                printf("Enter the input file name: ");
                scanf("%s", input_file);
                
                strcpy(full_path, DATA_DIR), strcat(full_path, "/"), strcat(full_path, input_file);
                
                if(RSA_public_encrypt(full_path, publicKey->e, publicKey->n))   /* Achieving confidentiality */
                    printf("Encryption Successfull! Output is stored as 'cipher.txt'.\n");
                else
                    printf("Encryption failed!\n");
                
                free_publicKey(publicKey);

                break;
            }

            case 'D': case 'd':   // Decrypting Message
            {
                strcpy(full_path, DATA_DIR);
                strcat(full_path, "/receiver_pKey.pem");
                PrivateKey *privateKey = load_privateKey(DATA_DIR "/receiver_pKey.pem");
                
                printf("Enter the name of the encrypted file: ");
                scanf("%s", encrypted_file);

                strcpy(full_path, DATA_DIR), strcat(full_path, "/"), strcat(full_path, encrypted_file);

                if(RSA_private_decrypt(full_path, privateKey->d, privateKey->n))
                    printf("Decryption Successfull! Output is stored as 'plain.txt'.\n");
                else
                    printf("Decryption failed!\n");
                
                free_privateKey(privateKey);

                break;
            }

            case 'S': case 's':   // Signing Message
            {
                char *mText = read_file(DATA_DIR "/input.txt");
                if(!mText){ break; }

                if(!generate_RSA_keys(DATA_DIR "/sender_pKey.pem")){   /* Message Sender's rsa key, for authentication */
                    printf("Key generation failed.\n");
                    break;
                }
                
                PrivateKey *privateKey = load_privateKey(DATA_DIR "/sender_pKey.pem");

                if(sign_message(mText, privateKey->d, privateKey->n, signature)){
                    printf("Message signed successfully.\n");
                    gmp_printf("Signature: %Zx\n", signature);
                }
                else
                    printf("Signing failed.\n");

                free(mText);
                free_privateKey(privateKey);

                break;
            }

            case 'V': case 'v':   // Verifying Message
            {
                char *dText = read_file(DATA_DIR "/plain.txt");

                PublicKey *publicKey = load_publicBytes(DATA_DIR "/sender_pKey.pem");

                if(verify_message(dText, signature, publicKey->e, publicKey->n))
                    printf("Message verified successfully: Message is authentic.\n");
                else
                    printf("Verification failed: Message is not authentic.\n");

                free(dText);
                free_publicKey(publicKey);

                break;
            }

            case 'X': case 'x':
                mpz_clear(signature);
                break;
            
            default:
                printf("Wrong choice.\n");
        }
    }while(choice != 'x' && choice != 'X');

    return 0;
}


