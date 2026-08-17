#ifndef RECORD_H
#define RECORD_H

#include <time.h>
#include <string>



struct Record {
    time_t timestamp;
    std::string data;
};

#endif  