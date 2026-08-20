#ifndef RECEIVER_H
#define RECEIVER_H
#include <string>
#include <set>
#include "record.h"
#include "serializer.h"
#include "crypt.h"

class Receiver {
    public:
        Receiver(AEAD aeadConfig, const std::vector<uint8_t>& key);
        std::string Receive();

    private:
        Crypt decrypter;
        std::set<uint32_t> seenRecIds;
        int ConstructRecord(Record& record);
};

#endif