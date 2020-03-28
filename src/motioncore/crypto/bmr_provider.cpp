#include "bmr_provider.h"

#include "communication/communication_layer.h"
#include "communication/fbs_headers/bmr_message_generated.h"
#include "communication/message_handler.h"
#include "data_storage/bmr_data.h"

namespace MOTION::Crypto {

class BMRMessageHandler : public Communication::MessageHandler {
 public:
  BMRMessageHandler(BMRData& data) : data_(data) {}
  void received_message(std::size_t, std::vector<std::uint8_t>&& message) override;

 private:
  BMRData& data_;
};

void BMRMessageHandler::received_message(std::size_t, std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  auto message = Communication::GetMessage(reinterpret_cast<std::uint8_t*>(raw_message.data()));
  auto message_type = message->message_type();
  switch (message_type) {
    case Communication::MessageType::BMRInputGate0: {
      auto id = Communication::GetBMRMessage(message->payload()->data())->gate_id();
      auto bmr_data = Communication::GetBMRMessage(message->payload()->data())->payload()->data();
      data_.MessageReceived(bmr_data, BMRDataType::input_step_0, id);
      break;
    }
    case Communication::MessageType::BMRInputGate1: {
      auto id = Communication::GetBMRMessage(message->payload()->data())->gate_id();
      auto bmr_data = Communication::GetBMRMessage(message->payload()->data())->payload()->data();
      data_.MessageReceived(bmr_data, BMRDataType::input_step_1, id);
      break;
    }
    case Communication::MessageType::BMRANDGate: {
      auto id = Communication::GetBMRMessage(message->payload()->data())->gate_id();
      auto bmr_data = Communication::GetBMRMessage(message->payload()->data())->payload()->data();
      data_.MessageReceived(bmr_data, BMRDataType::and_gate, id);
      break;
    }
    default: {
      assert(false);
      break;
    }
  }
}

BMRProvider::BMRProvider(Communication::CommunicationLayer& communication_layer)
    : communication_layer_(communication_layer),
      my_id_(communication_layer_.get_my_id()),
      num_parties_(communication_layer_.get_num_parties()),
      global_offset_(ENCRYPTO::block128_t::make_random()) {
  auto my_id = communication_layer_.get_my_id();
  data_.resize(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id) {
      continue;
    }
    data_.at(party_id) = std::make_unique<BMRData>();
  }
  communication_layer_.register_message_handler(
      [this](std::size_t party_id) {
        return std::make_shared<BMRMessageHandler>(*data_.at(party_id));
      },
      {MOTION::Communication::MessageType::BMRInputGate0,
       MOTION::Communication::MessageType::BMRInputGate1,
       MOTION::Communication::MessageType::BMRANDGate});
}

BMRProvider::~BMRProvider() {
  communication_layer_.deregister_message_handler(
      {MOTION::Communication::MessageType::BMRInputGate0,
       MOTION::Communication::MessageType::BMRInputGate1,
       MOTION::Communication::MessageType::BMRANDGate});
}

ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> BMRProvider::register_for_input_public_values(
    std::size_t input_owner, std::size_t gate_id, std::size_t bitlen) {
  assert(input_owner != my_id_);
  return data_.at(input_owner)->RegisterForInputPublicValues(gate_id, bitlen);
}

std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>>
BMRProvider::register_for_input_public_values(std::size_t gate_id, std::size_t num_blocks) {
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>> futures(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) = data_.at(party_id)->RegisterForInputPublicValues(gate_id, num_blocks);
  }
  return futures;
}

std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>>
BMRProvider::register_for_input_keys(std::size_t gate_id, std::size_t num_blocks) {
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>> futures(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) = data_.at(party_id)->RegisterForInputPublicKeys(gate_id, num_blocks);
  }
  return futures;
}

std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>>
BMRProvider::register_for_garbled_rows(std::size_t gate_id, std::size_t num_blocks) {
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>> futures(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) = data_.at(party_id)->RegisterForGarbledRows(gate_id, num_blocks);
  }
  return futures;
}

}  // namespace MOTION::Crypto
