//
//  main.cpp
//  cryptoWrapper
//
// dev: ing. Rodrigo Rayas Solorzano
// school: ITESO
// Libsodium library implementation

#include <iostream>
#include <iomanip>
#include "sodium.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <stdio.h>

using namespace std;
#define CHUNK_SIZE 4096

static int encryptFile(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char buf_in[CHUNK_SIZE];
    unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_t, *fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    unsigned char tag;
    fp_s = fopen("./text.txt", "rb");
    fp_t = fopen("cypher_text.txt", "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do
    {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int decryptFile(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buf_out[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_t, *fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    int ret = -1;
    unsigned char tag;
    fp_s = fopen("./cypher_text.txt", "rb");
    fp_t = fopen("./descyph_text.txt", "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0)
    {
        goto ret;
    }
    do
    {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0)
        {
            goto ret;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof)
        {
            goto ret;
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

int main(int argc, char *argv[])
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(key);
    int choice = 1;
    do
    {
        cout << "\n************************ -- MENU -- ***************************************\n";
        cout << "1. Generación y Recuperación de Claves hacia o desde 1 archivo\n";
        cout << "2. Cifrado de Archivos\n";
        cout << "3. Descifrado de Archivos\n";
        cout << "4. Firma de Archivos\n";
        cout << "5. Verificación de Firma de Archivos\n";
        cout << "0. Salir\n";
        cout << "************************ -- END MENU -- ***************************************\n";
        cout << "\nEnter 1, 2, 3, 4, 5 or 0 : ";
        cin >> choice;
        switch (choice)
        {
        case 1:
            cout << "\nGeneración y Recuperación de Claves\n";
            break;
        case 2:
            cout << "\nCifrado de Archivos\n ";
            encryptFile(key);
            break;
        case 3:
            cout << "\nDescifrado de Archivos\n ";
            decryptFile(key);
            break;
        case 4:
            cout << "\nFirma de Archivos\n";
            break;
        case 5:
            cout << "\nVerificación de firma de Archivos\n";
            break;
        case 0:
            break;
        default:
            cout << "\nPlease enter a correct option.\n";
            break;
        }
    } while (choice != 0);
    return 0;
}
