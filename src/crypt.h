#ifndef CRYPT_H
#define CRYPT_H

#include <openssl/evp.h>
#include <vector>
#include <cstdint>

typedef std::vector<uint8_t> Bytes;

enum AEAD {
    aes_128_gcm,
    chacha20_poly1305
};

class Crypt {
    public:
        Crypt(AEAD aeadconfig, const Bytes& key);
        void Encrypt(const Bytes& plainText,
                     const Bytes& nonce,
                     Bytes& cipherText,
                     Bytes& tag);
        void Decrypt(const Bytes& cipherText,
                     Bytes& plainText,
                     Bytes& tag);
                
    private:
        AEAD aeadConfig;
        Bytes key;
        Bytes GenerateNonce();
        Bytes GenerateAAD();


};

#endif