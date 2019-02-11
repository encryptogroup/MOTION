#ifndef DATASTORAGE_H
#define DATASTORAGE_H

#include "message_generated.h"
#include "hello_message_generated.h"

#include "utility/typedefs.h"

namespace ABYN {
  class DataStorage {
  public:
    DataStorage() {}

    ~DataStorage() {}

    void SetReceivedHelloMessage(std::vector<u8> &hello_message) { received_hello_message_ = std::move(hello_message); }

    const ABYN::Communication::HelloMessage *GetReceivedHelloMessage() {
      if (received_hello_message_.empty()) { return nullptr; }
      auto hm = ABYN::Communication::GetMessage(received_hello_message_.data());
      assert(hm != nullptr);
      return ABYN::Communication::GetHelloMessage(hm->payload()->data());
    }

    void SetSentHelloMessage(std::vector<u8> &hello_message) { sent_hello_message_ = std::move(hello_message); }

    void SetSentHelloMessage(const u8 *message, size_t size) {
      std::vector<u8> buf(message, message + size);
      SetSentHelloMessage(buf);
    }

    const ABYN::Communication::HelloMessage *GetSentHelloMessage() {
      if (sent_hello_message_.empty()) { return nullptr; }
      auto hm = ABYN::Communication::GetMessage(sent_hello_message_.data());
      assert(hm != nullptr);
      return ABYN::Communication::GetHelloMessage(hm->payload()->data());
    }

  private:
    std::vector<u8> received_hello_message_, sent_hello_message_;
  };
}

#endif //DATASTORAGE_H
