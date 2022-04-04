// MIT License
//
// Copyright (c) 2022 Oliver Schick
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "astra_provider.h"

#include "communication/message_handler.h"
#include "communication/message.h"
#include "communication/fbs_headers/astra_message_generated.h"
#include "communication/communication_layer.h"
    
namespace encrypto::motion::proto::astra {

std::mutex mm;

void printMap(std::map<std::size_t, ReusableFiberPromise<std::vector<uint8_t>>>& map, std::size_t id, std::string msg) {
    std::lock_guard<std::mutex> lock{mm};
    std::cout << "(map=" << &map << ", id=" << id << "): " << msg << std::endl;
}

class MessageHandler : public communication::MessageHandler {
 public:
  MessageHandler(Provider& provider) : provider_(provider) {}
  void ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& message) override;

 private:
  Provider& provider_;
};

void MessageHandler::ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  auto message = communication::GetMessage(reinterpret_cast<std::uint8_t*>(raw_message.data()));
  auto astra_message = communication::GetAstraMessage(message->payload()->data());
  auto gate_id = astra_message->gate_id();
  auto astra_data = astra_message->payload();
  std::vector<uint8_t> d(astra_data->data(), astra_data->data() + astra_data->size());
  provider_.PostData(gate_id, std::move(d));
}


Provider::Provider(communication::CommunicationLayer& communication_layer)
: communication_layer_{communication_layer} {

  communication_layer_.RegisterMessageHandler(
      [this](std::size_t) {
        return std::make_shared<MessageHandler>(*this);
      },
      {communication::MessageType::kAstraInputGate, communication::MessageType::kAstraOutputGate,
       communication::MessageType::kAstraSetupMultiplyGate, communication::MessageType::kAstraOnlineMultiplyGate, 
       communication::MessageType::kAstraSetupDotProductGate, communication::MessageType::kAstraOnlineDotProductGate});    
}

void Provider::PostData(std::size_t gate_id, std::vector<uint8_t>&& data) {
  std::lock_guard<std::mutex> lock{m_};
  auto [it, _] = messages_.try_emplace(gate_id);
  it->second.set_value(std::move(data));
}

Provider::Future Provider::RegisterReceivingGate(std::size_t gate_id) {
  std::lock_guard<std::mutex> lock{m_};
  auto [it, _] = messages_.try_emplace(gate_id);
  return it->second.get_future();
  
}

std::size_t Provider::UnregisterReceivingGate(std::size_t gate_id) {
  std::lock_guard<std::mutex> lock{m_};
  auto r = messages_.erase(gate_id);
  return r;
}

} // namespace encrypto::motion::proto::astra