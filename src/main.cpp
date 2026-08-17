#include "record.h"
#include "sender.h"
#include "receiver.h"
#include <string>
#include <iostream>

int main() {
    Sender senderObject;
    Receiver receiverObject;

    senderObject.Send("Sample data");
    
    std::string data = receiverObject.Receive();
    std::cout << data << std::endl;

    return 0;
}  