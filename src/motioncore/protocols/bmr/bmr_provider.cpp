#include "bmr_provider.h"

#include "communication/communication_layer.h"
#include "communication/message_manager.h"
#include "communication/message_manager.h"

namespace encrypto::motion::proto::bmr {

Provider::Provider(communication::CommunicationLayer& communication_layer)
    : communication_layer_(communication_layer),
      my_id_(communication_layer_.GetMyId()),
      number_of_parties_(communication_layer_.GetNumberOfParties()),
      global_offset_(Block128::MakeRandom()) {
  auto my_id = communication_layer_.GetMyId();
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id) {
      continue;
    }
  }
}

Provider::~Provider() {}

Provider::future_type Provider::RegisterForInputPublicValues(std::size_t input_owner,
                                                             std::size_t gate_id) {
  assert(input_owner != my_id_);
  return communication_layer_.GetMessageManager().RegisterReceive(
      input_owner, communication::MessageType::kBmrInputGate0, gate_id);
}

std::vector<Provider::future_type> Provider::RegisterForInputPublicValues(std::size_t gate_id) {
  auto futures{communication_layer_.GetMessageManager().RegisterReceiveAll(
      communication::MessageType::kBmrInputGate0, gate_id)};
  return futures;
}

std::vector<Provider::future_type> Provider::RegisterForInputKeys(std::size_t gate_id) {
  auto futures{communication_layer_.GetMessageManager().RegisterReceiveAll(
      communication::MessageType::kBmrInputGate1, gate_id)};
  return futures;
}

std::vector<Provider::future_type> Provider::RegisterForGarbledRows(std::size_t gate_id) {
  auto futures{communication_layer_.GetMessageManager().RegisterReceiveAll(
      communication::MessageType::kBmrAndGate, gate_id)};
  return futures;
}

}  // namespace encrypto::motion::proto::bmr
