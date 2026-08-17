#include <iostream>
#include "sender.h"
#include "record.h"
#include <string>
#include <time.h>
#include <fstream>
#include "serializer.h"
#include <cstdint>


using namespace std;

std::string transportMediumSender = "tm.bin";

int Sender::SendRecord(Record& record) {
    try {
        ofstream file(transportMediumSender);
        Serializer serializer;
        if (file.is_open()) {
            vector<uint8_t> byteStream = serializer.Serialize(record);
            for (uint8_t byte: byteStream) {
                file.put(byte);
            }
        } else return 1;
    } catch (const exception& e) {
        cout << e.what() << endl;
    } catch (...) {
        return 1;
    }
    return 0;
}

Record Sender::CreateRecord(const string& data, time_t timeStamp) {
    Record record{timeStamp, data};
    return record;
}

int Sender::Send(string data) {
    try {
        time_t sentTime = time(nullptr);
        Record record = CreateRecord(data, sentTime);
        return SendRecord(record);
    } catch (...) {
        return 1;
    }
}

