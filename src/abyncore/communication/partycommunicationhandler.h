#ifndef PARTYCOMMUNICATIONHANDLER_H
#define PARTYCOMMUNICATIONHANDLER_H

#include "utility/party.h"
#include "message_generated.h"

namespace ABYN::Communication{
  class PartyCommunicationHandler{
  public:
    PartyCommunicationHandler(ABYN::Party & party) : party_(party){
      //TODO:...
    };
    virtual ~PartyCommunicationHandler(){};
  private:
    ABYN::Party & party_;
    PartyCommunicationHandler() = delete;

    std::mutex mutex_;

    std::thread sender, receiver;
  };
}

#endif //PARTYCOMMUNICATIONHANDLER_H
