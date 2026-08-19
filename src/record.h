#ifndef RECORD_H
#define RECORD_H

#include <time.h>
#include <string>
#include <cstdint>


struct Record {
    uint32_t recId;
    time_t timestamp;
    std::string data;
};

#endif  