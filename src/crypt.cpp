#include "crypt.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>


using namespace std;

#define AES_KEY_SIZE 16
#define CHACHAPOLY_KEY_SIZE 32
#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16

Crypt::Crypt(AEAD aeadConfig, const vector<uint8_t>& userkey) {
    if ((aeadConfig == aes_128_gcm && userkey.size() != AES_KEY_SIZE) || 
         (aeadConfig == chacha20_poly1305 && userkey.size() != CHACHAPOLY_KEY_SIZE)) {
            throw std::runtime_error("Invalid key size\n");
    }; 
    this->key = userkey;
    this->aeadConfig = aeadConfig;
}

Bytes Crypt::Encrypt (const Bytes& plainText,
                     const Bytes& aad) {
    
    bool encryptionFlag;
    Bytes nonce, cipherText, tag;

    switch (aeadConfig)
    {
    case aes_128_gcm:
        encryptionFlag = EncryptAES_GCM(plainText, aad, cipherText, nonce, tag);
        break;
    
    case chacha20_poly1305:
        encryptionFlag = EncryptChaCha_Poly(plainText, cipherText, tag);
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
    nonce = GenerateNonce(this->aeadConfig);

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
                            Bytes& cipherText, 
                            Bytes& tag) {
                                return false;
}   

Bytes Crypt::GenerateNonce(AEAD aeadConfig) {
    Bytes nonce(AES_GCM_IV_LEN);

    if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
        throw std::runtime_error("Failed to generate nonce");
    }

    return nonce;
}