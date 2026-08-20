#include "crypt.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>


using namespace std;

#define AES_KEY_SIZE 16
#define CHACHA_POLY_KEY_SIZE 32
#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16
#define CHACHA_POLY_NONCE_LEN 12
#define CHACHA_POLY_TAG_LEN 16
#define AAD_LEN 4
#define NONCE_LEN 12
#define TAG_LEN 16

Crypt::Crypt(AEAD aeadConfig, const vector<uint8_t>& userkey) {
    if ((aeadConfig == aes_128_gcm && userkey.size() != AES_KEY_SIZE) || 
         (aeadConfig == chacha20_poly1305 && userkey.size() != CHACHA_POLY_KEY_SIZE)) {
            std::cout << "keysize: " << userkey.size() << endl;
            throw std::runtime_error("Invalid key size\n");
    }; 
    this->key = userkey;
    this->aeadConfig = aeadConfig;
}

Bytes Crypt::Encrypt (const Bytes& plainText,
                     const Bytes& aad) {
    
    bool encryptionFlag = false;
    Bytes nonce, cipherText, tag;

    switch (aeadConfig)
    {
    case aes_128_gcm:
        encryptionFlag = EncryptAES_GCM(plainText, aad, cipherText, nonce, tag);
        break;

    case chacha20_poly1305:
        encryptionFlag = EncryptChaCha_Poly(plainText, aad, cipherText, nonce, tag);
        break;
    }
    
    if (encryptionFlag == false) {
        std::cout << "Encryption Failure" << std::endl;
        return {};
    } else {
        Bytes secureStream;

        secureStream.insert(secureStream.end(), aad.begin(), aad.end());
        secureStream.insert(secureStream.end(), nonce.begin(), nonce.end());
        secureStream.insert(secureStream.end(), cipherText.begin(), cipherText.end());
        secureStream.insert(secureStream.end(), tag.begin(), tag.end());
        
        return secureStream;
    }

}

bool Crypt::EncryptAES_GCM(const Bytes& plainText, 
                            const Bytes& aad,
                            Bytes& cipherText,
                            Bytes& nonce,
                            Bytes& tag) {
    int len = 0;
    int cipherLen = 0;
    nonce = GenerateNonce(aes_128_gcm);

    // Init encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);\
    
    // Set IV len
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr);

    // Set key and IV 
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, this->key.data(), nonce.data());

    // AAD
    EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());
    
    // Encryption
    cipherText.resize(plainText.size());
    EVP_EncryptUpdate(ctx, cipherText.data(), &len, plainText.data(), plainText.size());
    cipherLen = len;

    // Finalizing encryption
    EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len);

    cipherLen += len;
    cipherText.resize(cipherLen);

    // Get Authentication tag
    tag.resize(AES_GCM_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    return true;

}

bool Crypt::EncryptChaCha_Poly(const Bytes& plainText, 
                            const Bytes& aad,
                            Bytes& cipherText,
                            Bytes& nonce,
                            Bytes& tag) {
    int len = 0;
    int cipherLen = 0;
    nonce = GenerateNonce(chacha20_poly1305);

    // Init encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);\
    
    // Set IV len
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CHACHA_POLY_NONCE_LEN, nullptr);

    // Set key and IV 
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, this->key.data(), nonce.data());

    // AAD
    EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());
    
    // Encryption
    cipherText.resize(plainText.size());
    EVP_EncryptUpdate(ctx, cipherText.data(), &len, plainText.data(), plainText.size());
    cipherLen = len;

    // Finalizing encryption
    EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len);

    cipherLen += len;
    cipherText.resize(cipherLen);

    // Get Authentication tag
    tag.resize(CHACHA_POLY_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CHACHA_POLY_TAG_LEN, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    return true;
}   

void Crypt::Decrypt(const Bytes& cipherText,
                     Bytes& plainText,
                     Bytes& aad,
                     Bytes& tag) {
    if (cipherText.size() < AAD_LEN + NONCE_LEN + TAG_LEN) {
        throw std::runtime_error("Malformed secure stream\n");
    }

    aad.assign(cipherText.begin(), cipherText.begin() + AAD_LEN);
    Bytes nonce(cipherText.begin() + AAD_LEN, cipherText.begin() + AAD_LEN + NONCE_LEN);
    Bytes actualCipherText(cipherText.begin() + AAD_LEN + NONCE_LEN, cipherText.end() - TAG_LEN);
    tag.assign(cipherText.end() - TAG_LEN, cipherText.end());

    bool decryptionFlag = false;

    switch (aeadConfig)
    {
    case aes_128_gcm:
        decryptionFlag = DecryptAES_GCM(actualCipherText, aad, nonce, tag, plainText);
        break;

    case chacha20_poly1305:
        decryptionFlag = DecryptChaCha_Poly(actualCipherText, aad, nonce, tag, plainText);
        break;
    }

    if (decryptionFlag == false) {
        throw std::runtime_error("Decryption failed: authentication tag mismatch\n");
    }
}

bool Crypt::DecryptAES_GCM(const Bytes& cipherText,
                            const Bytes& aad,
                            const Bytes& nonce,
                            const Bytes& tag,
                            Bytes& plainText) {
    int len = 0;
    int plainLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr);

    EVP_DecryptInit_ex(ctx, nullptr, nullptr, this->key.data(), nonce.data());

    EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());

    plainText.resize(cipherText.size());
    EVP_DecryptUpdate(ctx, plainText.data(), &len, cipherText.data(), cipherText.size());
    plainLen = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void*)tag.data());

    int ret = EVP_DecryptFinal_ex(ctx, plainText.data() + len, &len);
    plainLen += len;
    plainText.resize(plainLen);

    EVP_CIPHER_CTX_free(ctx);

    return ret > 0;
}

bool Crypt::DecryptChaCha_Poly(const Bytes& cipherText,
                            const Bytes& aad,
                            const Bytes& nonce,
                            const Bytes& tag,
                            Bytes& plainText) {
    int len = 0;
    int plainLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CHACHA_POLY_NONCE_LEN, nullptr);

    EVP_DecryptInit_ex(ctx, nullptr, nullptr, this->key.data(), nonce.data());

    EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());

    plainText.resize(cipherText.size());
    EVP_DecryptUpdate(ctx, plainText.data(), &len, cipherText.data(), cipherText.size());
    plainLen = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CHACHA_POLY_TAG_LEN, (void*)tag.data());

    int ret = EVP_DecryptFinal_ex(ctx, plainText.data() + len, &len);
    plainLen += len;
    plainText.resize(plainLen);

    EVP_CIPHER_CTX_free(ctx);

    return ret > 0;
}

Bytes Crypt::GenerateNonce(AEAD aeadConfig) {
    int nonceSize = (aeadConfig == aes_128_gcm) ? (AES_GCM_IV_LEN) : (CHACHA_POLY_NONCE_LEN);
    Bytes nonce(nonceSize);

    if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
        throw std::runtime_error("Failed to generate nonce");
    }

    return nonce;
}