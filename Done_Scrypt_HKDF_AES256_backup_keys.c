#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/scrypt.h>

#define KEY_LENGTH 32
#define IV_LENGTH 16

void hkdf_scrypt(const char *password, const char *salt, size_t length, int n, int r, int p, unsigned char *okm) {
    unsigned char prk[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), salt, strlen(salt), (unsigned char*)password, strlen(password), prk, NULL);

    unsigned char t[EVP_MAX_MD_SIZE];
    unsigned char info[] = "Scrypt key derivation";
    unsigned char concat[EVP_MAX_MD_SIZE + sizeof(info) + 1];
    size_t t_len = 0;

    while (t_len < length) {
        memcpy(concat, t, t_len);
        memcpy(concat + t_len, info, sizeof(info));
        concat[t_len + sizeof(info)] = t_len + 1;

        HMAC(EVP_sha256(), prk, sizeof(prk), concat, t_len + sizeof(info) + 1, t, NULL);

        scrypt(t, t_len, salt, strlen(salt), n, r, p, okm + t_len, length - t_len);
        t_len += sizeof(t);
    }
}

void encrypt_file(const char *file_path, const unsigned char *key) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", file_path);
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *plaintext = (unsigned char *)malloc(file_size);
    if (!plaintext) {
        fclose(file);
        printf("Failed to allocate memory for plaintext\n");
        return;
    }

    size_t read_bytes = fread(plaintext, 1, file_size, file);
    if (read_bytes != file_size) {
        fclose(file);
        free(plaintext);
        printf("Failed to read file: %s\n", file_path);
        return;
    }

    fclose(file);

    unsigned char iv[IV_LENGTH];
    RAND_bytes(iv, IV_LENGTH);

    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 8 * KEY_LENGTH, &aes_key) != 0) {
        free(plaintext);
        printf("Failed to set AES encryption key\n");
        return;
    }

    size_t padded_plaintext_length = ((read_bytes + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *padded_plaintext = (unsigned char *)malloc(padded_plaintext_length);
    if (!padded_plaintext) {
        free(plaintext);
        printf("Failed to allocate memory for padded plaintext\n");
        return;
    }

    memcpy(padded_plaintext, plaintext, read_bytes);
    memset(padded_plaintext + read_bytes, 0, padded_plaintext_length - read_bytes);

    unsigned char ciphertext[padded_plaintext_length];
    AES_cbc_encrypt(padded_plaintext, ciphertext, padded_plaintext_length, &aes_key, iv, AES_ENCRYPT);

    file = fopen(file_path, "wb");
    if (!file) {
        free(plaintext);
        free(padded_plaintext);
        printf("Failed to open file for writing: %s\n", file_path);
        return;
    }

    fwrite(iv, 1, IV_LENGTH, file);
    fwrite(ciphertext, 1, padded_plaintext_length, file);

    fclose(file);
    free(plaintext);
    free(padded_plaintext);
}

void decrypt_file(const char *file_path, const unsigned char *key) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", file_path);
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *ciphertext = (unsigned char *)malloc(file_size);
    if (!ciphertext) {
        fclose(file);
        printf("Failed to allocate memory for ciphertext\n");
        return;
    }

    size_t read_bytes = fread(ciphertext, 1, file_size, file);
    if (read_bytes != file_size) {
        fclose(file);
        free(ciphertext);
        printf("Failed to read file: %s\n", file_path);
        return;
    }

    fclose(file);

    unsigned char iv[IV_LENGTH];
    memcpy(iv, ciphertext, IV_LENGTH);

    AES_KEY aes_key;
    if (AES_set_decrypt_key(key, 8 * KEY_LENGTH, &aes_key) != 0) {
        free(ciphertext);
        printf("Failed to set AES decryption key\n");
        return;
    }

    size_t ciphertext_length = file_size - IV_LENGTH;
    unsigned char *padded_plaintext = (unsigned char *)malloc(ciphertext_length);
    if (!padded_plaintext) {
        free(ciphertext);
        printf("Failed to allocate memory for padded plaintext\n");
        return;
    }

    AES_cbc_encrypt(ciphertext + IV_LENGTH, padded_plaintext, ciphertext_length, &aes_key, iv, AES_DECRYPT);

    size_t plaintext_length;
    if (padded_plaintext[ciphertext_length - 1] <= AES_BLOCK_SIZE) {
        plaintext_length = ciphertext_length - padded_plaintext[ciphertext_length - 1];
    } else {
        plaintext_length = ciphertext_length;
    }

    unsigned char *plaintext = (unsigned char *)malloc(plaintext_length);
    if (!plaintext) {
        free(ciphertext);
        free(padded_plaintext);
        printf("Failed to allocate memory for plaintext\n");
        return;
    }

    memcpy(plaintext, padded_plaintext, plaintext_length);

    file = fopen(file_path, "wb");
    if (!file) {
        free(ciphertext);
        free(padded_plaintext);
        free(plaintext);
        printf("Failed to open file for writing: %s\n", file_path);
        return;
    }

    fwrite(plaintext, 1, plaintext_length, file);

    fclose(file);
    free(ciphertext);
    free(padded_plaintext);
    free(plaintext);
}

void encrypt_folder(const char *folder_path, const unsigned char *key, const char *mode) {
    double start_time = clock();
    DIR *dir = opendir(folder_path);
    if (!dir) {
        printf("Failed to open directory: %s\n", folder_path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char file_path[PATH_MAX];
            snprintf(file_path, sizeof(file_path), "%s/%s", folder_path, entry->d_name);

            if (strcmp(mode, "encrypt") == 0) {
                encrypt_file(file_path, key);
                printf("Encrypted: %s\n", file_path);
            } else if (strcmp(mode, "decrypt") == 0) {
                decrypt_file(file_path, key);
                printf("Decrypted: %s\n", file_path);
            }

            // Monitor system resources while processing files
            float cpu_percent = psutil_cpu_percent(NULL, 0.1);
            float memory_percent = psutil_virtual_memory()->percent;
            printf("CPU Usage: %.2f%% - Memory Usage: %.2f%%\n", cpu_percent, memory_percent);
        }
    }

    closedir(dir);

    double end_time = clock();
    double execution_time = (end_time - start_time) / CLOCKS_PER_SEC;
    printf("Execution Time: %.3f seconds (%.3f milliseconds)\n", execution_time, execution_time * 1000);
}

int main() {
    const char password[256];
    const char salt[33];
    unsigned char derived_key[KEY_LENGTH];

    printf("Enter the password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    printf("Enter the salt: ");
    fgets(salt, sizeof(salt), stdin);
    salt[strcspn(salt, "\n")] = '\0';

    int length, n, r, p;
    printf("Enter the desired key length in bytes: ");
    scanf("%d", &length);
    printf("Enter the value for 'n': ");
    scanf("%d", &n);
    printf("Enter the value for 'r': ");
    scanf("%d", &r);
    printf("Enter the value for 'p': ");
    scanf("%d", &p);

    hkdf_scrypt(password, salt, length, n, r, p, derived_key);

    // Encode the derived key using base64
    char *encoded_key = base64_encode(derived_key, KEY_LENGTH);

    char mode[10];
    printf("Enter the mode ('encrypt' or 'decrypt'): ");
    scanf("%s", mode);

    if (strcmp(mode, "encrypt") == 0) {
        // Store the encoded key in a secure location (e.g., a file or database)
        FILE *file = fopen("backup_key.txt", "w");
        if (file) {
            fputs(encoded_key, file);
            fclose(file);
        } else {
            printf("Failed to open file for writing: backup_key.txt\n");
        }
    }

    char folder_path[PATH_MAX];
    printf("Enter the folder path: ");
    scanf("%s", folder_path);

    encrypt_folder(folder_path, derived_key, mode);

    free(encoded_key);

    return 0;
}
