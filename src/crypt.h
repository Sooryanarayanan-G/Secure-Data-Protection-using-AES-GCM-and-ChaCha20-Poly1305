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
        Bytes Encrypt(const Bytes& plainText,
                     const Bytes& aad);
        void Decrypt(const Bytes& cipherText,
                     Bytes& plainText,
                     Bytes& aad,
                     Bytes& tag);

    private:
        AEAD aeadConfig;
        Bytes key;
        Bytes GenerateNonce(AEAD aeadConfig);
        bool EncryptAES_GCM(const Bytes& plainText,
                            const Bytes& aad,
                            Bytes& cipherText,
                            Bytes& nonce,
                            Bytes& tag);
        bool EncryptChaCha_Poly(const Bytes& plainText,
                            const Bytes& aad,
                            Bytes& cipherText,
                            Bytes& nonce,
                            Bytes& tag);
        bool DecryptAES_GCM(const Bytes& cipherText,
                            const Bytes& aad,
                            const Bytes& nonce,
                            const Bytes& tag,
                            Bytes& plainText);
        bool DecryptChaCha_Poly(const Bytes& cipherText,
                            const Bytes& aad,
                            const Bytes& nonce,
                            const Bytes& tag,
                            Bytes& plainText);

};

#endif