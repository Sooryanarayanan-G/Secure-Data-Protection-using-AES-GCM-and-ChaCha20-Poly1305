#ifndef SENDER_H
#define SENDER_H

#include <string>
#include "record.h"

class Sender {
    private:
        int SendRecord(Record& record);
        Record CreateRecord(const std::string& data, time_t timeStamp);
        
    public:
        Sender() = default;
        int Send(std::string data);
};

#endif
