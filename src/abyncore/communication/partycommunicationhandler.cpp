#include "partycommunicationhandler.h"

namespace ABYN::Communication {

  void PartyCommunicationHandler::ActAsSerder(const BoostSocketPtr &socket, std::deque<Message> &deque_send,
                                              const bool &continue_communication) {
    while (continue_communication) {
      bool some_work_was_done = false;
//TODO:implement message handling
      if (!some_work_was_done) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

  void PartyCommunicationHandler::ActAsReceiver(const BoostSocketPtr &socket, std::deque<Message> &deque_send,
                                                const bool &continue_communication) {
    while (continue_communication) {
      bool some_work_was_done = false;
//TODO:implement message handling
      if (!some_work_was_done) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

}