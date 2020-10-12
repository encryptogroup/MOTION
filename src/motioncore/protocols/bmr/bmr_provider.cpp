#include "bmr_provider.h"
#include "bmr_data.h"

#include "communication/communication_layer.h"
#include "communication/fbs_headers/bmr_message_generated.h"
#include "communication/message_handler.h"

namespace encrypto::motion::proto::bmr {

class MessageHandler : public communication::MessageHandler {
 public:
  MessageHandler(Data& data) : data_(data) {}
  void ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& message) override;

 private:
  Data& data_;
};

void MessageHandler::ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  auto message = communication::GetMessage(reinterpret_cast<std::uint8_t*>(raw_message.data()));
  auto message_type = message->message_type();
  switch (message_type) {
    case communication::MessageType::kBmrInputGate0: {
      auto id = communication::GetBmrMessage(message->payload()->data())->gate_id();
      auto bmr_data = communication::GetBmrMessage(message->payload()->data())->payload()->data();
      data_.MessageReceived(bmr_data, DataType::kInputStep0, id);
      break;
    }
    case communication::MessageType::kBmrInputGate1: {
      auto id = communication::GetBmrMessage(message->payload()->data())->gate_id();
      auto bmr_data = communication::GetBmrMessage(message->payload()->data())->payload()->data();
      data_.MessageReceived(bmr_data, DataType::kInputStep1, id);
      break;
    }
    case communication::MessageType::kBmrAndGate: {
      auto id = communication::GetBmrMessage(message->payload()->data())->gate_id();
      auto bmr_data = communication::GetBmrMessage(message->payload()->data())->payload()->data();
      data_.MessageReceived(bmr_data, DataType::kAndGate, id);
      break;
    }
    default: {
      assert(false);
      break;
    }
  }
}

Provider::Provider(communication::CommunicationLayer& communication_layer)
    : communication_layer_(communication_layer),
      my_id_(communication_layer_.GetMyId()),
      number_of_parties_(communication_layer_.GetNumberOfParties()),
      global_offset_(Block128::MakeRandom()) {
  auto my_id = communication_layer_.GetMyId();
  data_.resize(number_of_parties_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id) {
      continue;
    }
    data_.at(party_id) = std::make_unique<Data>();
  }
  communication_layer_.RegisterMessageHandler(
      [this](std::size_t party_id) {
        return std::make_shared<MessageHandler>(*data_.at(party_id));
      },
      {communication::MessageType::kBmrInputGate0, communication::MessageType::kBmrInputGate1,
       communication::MessageType::kBmrAndGate});
}

Provider::~Provider() {
  communication_layer_.DeregisterMessageHandler({communication::MessageType::kBmrInputGate0,
                                                 communication::MessageType::kBmrInputGate1,
                                                 communication::MessageType::kBmrAndGate});
}

ReusableFiberFuture<BitVector<>> Provider::RegisterForInputPublicValues(std::size_t input_owner,
                                                                        std::size_t gate_id,
                                                                        std::size_t bitlength) {
  assert(input_owner != my_id_);
  return data_.at(input_owner)->RegisterForInputPublicValues(gate_id, bitlength);
}

std::vector<ReusableFiberFuture<BitVector<>>> Provider::RegisterForInputPublicValues(
    std::size_t gate_id, std::size_t number_of_blocks) {
  std::vector<ReusableFiberFuture<BitVector<>>> futures(number_of_parties_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) =
        data_.at(party_id)->RegisterForInputPublicValues(gate_id, number_of_blocks);
  }
  return futures;
}

std::vector<ReusableFiberFuture<Block128Vector>> Provider::RegisterForInputKeys(
    std::size_t gate_id, std::size_t number_of_blocks) {
  std::vector<ReusableFiberFuture<Block128Vector>> futures(number_of_parties_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) =
        data_.at(party_id)->RegisterForInputPublicKeys(gate_id, number_of_blocks);
  }
  return futures;
}

std::vector<ReusableFiberFuture<Block128Vector>> Provider::RegisterForGarbledRows(
    std::size_t gate_id, std::size_t number_of_blocks) {
  std::vector<ReusableFiberFuture<Block128Vector>> futures(number_of_parties_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) = data_.at(party_id)->RegisterForGarbledRows(gate_id, number_of_blocks);
  }
  return futures;
}

}  // namespace encrypto::motion::proto::bmr
