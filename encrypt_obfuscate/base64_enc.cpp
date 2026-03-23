#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>          // ← THÊM DÒNG NÀY
#include <stdint.h>

// ====================== CODE BASE64 CỦA BẠN (giữ nguyên) ======================
static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static char* decoding_table = NULL;
static int mod_table[] = { 0, 2, 1 };

void build_decoding_table() {
    decoding_table = (char*)malloc(256);
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char)encoding_table[i]] = i;
}

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = (char*)malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    if (decoding_table == NULL) build_decoding_table();

    // Kiểm tra độ dài
    if (input_length == 0 || input_length % 4 != 0) {
        printf("Decode error: length %zu not divisible by 4\n", input_length);
        return NULL;
    }

    *output_length = input_length / 4 * 3;
    if (input_length > 0 && data[input_length - 1] == '=') (*output_length)--;
    if (input_length > 1 && data[input_length - 2] == '=') (*output_length)--;

    if (*output_length == 0) return (unsigned char*)malloc(0); // edge case

    unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    size_t i = 0, j = 0;
    while (i < input_length) {
        uint32_t sextet_a = (i < input_length && data[i] != '=') ? (unsigned char)decoding_table[(unsigned char)data[i]] : 0;
        if (sextet_a > 63) { printf("Invalid char at pos %zu: %c\n", i, data[i]); free(decoded_data); return NULL; }
        i++;

        uint32_t sextet_b = (i < input_length && data[i] != '=') ? (unsigned char)decoding_table[(unsigned char)data[i]] : 0;
        if (sextet_b > 63) { printf("Invalid char at pos %zu: %c\n", i, data[i]); free(decoded_data); return NULL; }
        i++;

        uint32_t sextet_c = (i < input_length && data[i] != '=') ? (unsigned char)decoding_table[(unsigned char)data[i]] : 0;
        if (sextet_c > 63) { printf("Invalid char at pos %zu: %c\n", i, data[i]); free(decoded_data); return NULL; }
        i++;

        uint32_t sextet_d = (i < input_length && data[i] != '=') ? (unsigned char)decoding_table[(unsigned char)data[i]] : 0;
        if (sextet_d > 63) { printf("Invalid char at pos %zu: %c\n", i, data[i]); free(decoded_data); return NULL; }
        i++;

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0) & 0xFF;
    }

    return decoded_data;
}

void base64_cleanup() {
    free(decoding_table);
}

int main() {
    // Bắt buộc set UTF-8 cho console
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    const char* text = "Hello Việt Nam! 😊";

    printf("Do dai chuoi: %zu byte\n", strlen(text));
    printf("Chuoi goc : %s\n", text);

    size_t enc_len;
    char* encoded = base64_encode((const unsigned char*)text, strlen(text), &enc_len);
    if (encoded) {
        printf("Encoded  : %.*s\n", (int)enc_len, encoded);
    }

    if (encoded) {
        printf("Encoded  : %.*s (length: %zu)\n", (int)enc_len, encoded, enc_len);

        printf("Check 1 - Before decode\n");
        size_t dec_len = 0;
        unsigned char* decoded = base64_decode(encoded, enc_len, &dec_len);
        printf("Check 2 - After decode (returned %p, len %zu)\n", (void*)decoded, dec_len);

        if (decoded) {
            printf("Decoded  : ");
            for (size_t k = 0; k < dec_len; k++) {
                unsigned char c = decoded[k];
                if (c >= 32 && c <= 126) putchar(c);
                else printf("\\x%02X", c);
            }
            printf("\n");
            free(decoded);
        }
        else {
            printf("Decode returned NULL - check error above\n");
        }
        free(encoded);
    }

    base64_cleanup();
    printf("\nNhan phim bat ky de thoat...\n");
    getchar();
    return 0;
}