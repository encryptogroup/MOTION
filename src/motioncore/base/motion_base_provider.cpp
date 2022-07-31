// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#include "motion_base_provider.h"

#include "communication/communication_layer.h"
#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/hello_message.h"
#include "communication/message_manager.h"
#include "primitives/sharing_randomness_generator.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

BaseProvider::BaseProvider(communication::CommunicationLayer& communication_layer)
    : communication_layer_(communication_layer),
      logger_(communication_layer_.GetLogger()),
      number_of_parties_(communication_layer_.GetNumberOfParties()),
      my_id_(communication_layer_.GetMyId()),
      my_randomness_generators_(number_of_parties_),
      their_randomness_generators_(number_of_parties_),
      hello_message_futures_(communication_layer_.GetMessageManager().RegisterReceiveAll(
          communication::MessageType::kHelloMessage, 0)) {}

BaseProvider::~BaseProvider() {}

void BaseProvider::Setup() {
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("BaseProvider::Setup: running setup");
    }
  }

  // generate share, broadcast, wait for messages, xor
  aes_fixed_key_ = RandomVector<std::uint8_t>(16);
  std::vector<std::vector<std::uint8_t>> my_seeds;
  std::generate_n(std::back_inserter(my_seeds), number_of_parties_,
                  [] { return RandomVector<std::uint8_t>(32); });
  std::vector<std::uint8_t> global_seed = RandomVector<std::uint8_t>(32);

  // prepare and send HelloMessage
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto msg_builder = communication::BuildHelloMessage(
        my_id_, party_id, number_of_parties_, &my_seeds.at(party_id), &global_seed, &aes_fixed_key_,
        /* TODO: configuration_->GetOnlineAfterSetup()*/ true, kMotionVersionMajor,
        kMotionVersionMinor, kMotionVersionPatch);
    communication_layer_.SendMessage(party_id, msg_builder.Release());
  }
  // initialize my randomness generators
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    my_randomness_generators_.at(party_id) =
        std::make_unique<primitives::SharingRandomnessGenerator>(party_id);
    my_randomness_generators_.at(party_id)->Initialize(
        reinterpret_cast<std::uint8_t*>(my_seeds.at(party_id).data()));
    their_randomness_generators_.at(party_id) =
        std::make_unique<primitives::SharingRandomnessGenerator>(party_id);
  }
  // receive HelloMessages from other and initialize
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& f{hello_message_futures_[party_id > my_id_ ? party_id - 1 : party_id]};
    auto bytes{f.get()};
    auto message{communication::GetMessage(bytes.data())};
    auto hello_message{communication::GetHelloMessage(message->payload()->data())};
    auto global_sharing_seed = hello_message->global_sharing_seed();
    auto aes_key = hello_message->fixed_key_aes_seed();
    // add received share to the global seed
    std::transform(global_seed.data(), global_seed.data() + global_seed.size(),
                   global_sharing_seed->data(), global_seed.data(),
                   [](auto a, auto b) { return a ^ b; });
    // add received share to the fixed aes key
    std::transform(aes_fixed_key_.data(), aes_fixed_key_.data() + aes_fixed_key_.size(),
                   aes_key->data(), aes_fixed_key_.data(), [](auto a, auto b) { return a ^ b; });
    auto their_seed = hello_message->input_sharing_seed();
    // initialize randomness generator of the other party
    their_randomness_generators_.at(party_id)->Initialize(their_seed->data());
  }
  // initialize global randomness generator
  global_randomness_generator_ = std::make_unique<primitives::SharingRandomnessGenerator>(-1);
  global_randomness_generator_->Initialize(global_seed.data());

  SetSetupIsReady();
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("BaseProvider::Setup: setup completed");
    }
  }
}

}  // namespace encrypto::motion
