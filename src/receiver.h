#ifndef RECEIVER_H
#define RECEIVER_H
#include <string>
#include "record.h"
#include "serializer.h"
#include "crypt.h"

class Receiver {
    public:
        Receiver(AEAD aeadConfig, const std::vector<uint8_t>& key);
        std::string Receive();

    private:
        Crypt decrypter;
        int ConstructRecord(Record& record);
};

#endif