#ifndef DATASTORAGE_H
#define DATASTORAGE_H

#include "communication/hellomessage.h"


namespace ABYN{
  class DataStorage{
  public:
    DataStorage(){}
    ~DataStorage(){}

    void SetHelloMessage(std::vector<u8> && hello_message){hello_message_ = std::move(hello_message);}

  private:
    std::vector<u8> hello_message_;
  };
}

#endif //DATASTORAGE_H
