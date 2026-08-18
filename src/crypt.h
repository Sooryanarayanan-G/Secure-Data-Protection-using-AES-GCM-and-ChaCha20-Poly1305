#ifndef CRYPT_H
#define CRYPT_H

#include <openssl/evp.h>
#include <vector>
#include <cstdint>

enum AEAD {
    aes_128_gcm,
    chacha20_poly1305
};

class Crypt {
    public:
        Crypt(AEAD aeadconfig);
        void Encrypt(const std::vector<uint8_t>& plainText,
                     std::vector<uint8_t>& cipherText,
                     std::vector<uint8_t>& tag);
        void Decrypt(const std::vector<uint8_t>& cipherText,
                     std::vector<uint8_t>& plainText,
                     std::vector<uint8_t>& tag);
                
    private:
        AEAD aeadConfig;
        std::vector<uint8_t> GenerateNonce();
        std::vector<uint8_t> GenerateAAD();


};

#endif