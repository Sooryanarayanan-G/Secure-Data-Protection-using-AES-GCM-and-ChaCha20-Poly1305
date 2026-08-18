#ifndef SENDER_H
#define SENDER_H

#include <string>
#include <cstdint>
#include "record.h"
#include "serializer.h"
#include "crypt.h"

class Sender {
    private:
        Serializer serializer;
        Crypt encrypter;
        int SendRecord(Record& record);
        Record CreateRecord(const std::string& data, time_t timeStamp);
        
    public:
        Sender(AEAD aeadConfig, const std::vector<uint8_t>& key);
        int Send(std::string data);
};

#endif
