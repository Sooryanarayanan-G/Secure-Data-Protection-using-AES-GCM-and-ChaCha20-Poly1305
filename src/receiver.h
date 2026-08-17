#ifndef RECEIVER_H
#define RECEIVER_H
#include <string>
#include "record.h"
#include "serializer.h"

class Receiver {
    public:
        std::string Receive();

    private:
        int ConstructRecord(Record& record);
};

#endif