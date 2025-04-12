#include "common.h"
#include "readFile.h"

char* read_file(char* file_name){                        // reading the file in string for hashing
    FILE *fptr = fopen(file_name, "rb");
    if(!fptr){
        perror("Error opening file for reading");
        return NULL;
    }

    int size = 0;
    fseek(fptr, 0, SEEK_END);
    size = ftell(fptr);                                  // tells the number of character in file
    char *str = malloc((size+1)*sizeof(char));
    if(!str){
        perror("Memory aallocation failed");
        return NULL;
    }

    rewind(fptr);

    int bytesRead = (int)fread(str, 1, size, fptr);
    str[size] = '\0';
    
    if(bytesRead != size){
        perror("Warning: Could not read the entire file");
        fclose(fptr);
        free(str);
        return NULL;
    }

    fclose(fptr);
    return str;
}