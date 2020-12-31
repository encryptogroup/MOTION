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
#include "output_message_handler.h"

#include "communication/communication_layer.h"
#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/hello_message.h"
#include "communication/message_handler.h"
#include "primitives/sharing_randomness_generator.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

// Handler for messages of type HelloMessage
struct HelloMessageHandler : public communication::MessageHandler {
  // Create a handler object for a given party
  HelloMessageHandler(std::size_t number_of_parties, std::shared_ptr<Logger> logger)
      : logger_(logger),
        fixed_key_aes_seed_promises(number_of_parties),
        randomness_sharing_seed_promises(number_of_parties) {
    std::transform(std::begin(fixed_key_aes_seed_promises), std::end(fixed_key_aes_seed_promises),
                   std::back_inserter(fixed_key_aes_seed_futures),
                   [](auto& p) { return p.get_future(); });
    std::transform(std::begin(randomness_sharing_seed_promises),
                   std::end(randomness_sharing_seed_promises),
                   std::back_inserter(randomness_sharing_seed_futures),
                   [](auto& p) { return p.get_future(); });
  }

  // Method which is called on received messages.
  void ReceivedMessage(std::size_t party_id, std::vector<std::uint8_t>&& message) override;

  ReusableFuture<std::vector<std::uint8_t>> GetRandomnessSharingSeedFuture();

  std::shared_ptr<Logger> logger_;
  std::vector<ReusablePromise<std::vector<std::uint8_t>>> fixed_key_aes_seed_promises;
  std::vector<ReusableFuture<std::vector<std::uint8_t>>> fixed_key_aes_seed_futures;
  std::vector<ReusablePromise<std::vector<std::uint8_t>>> randomness_sharing_seed_promises;
  std::vector<ReusableFuture<std::vector<std::uint8_t>>> randomness_sharing_seed_futures;
};

void HelloMessageHandler::ReceivedMessage(std::size_t party_id,
                                          std::vector<std::uint8_t>&& hello_message) {
  assert(!hello_message.empty());
  auto message = communication::GetMessage(reinterpret_cast<std::uint8_t*>(hello_message.data()));
  auto hello_message_pointer = communication::GetHelloMessage(message->payload()->data());

  auto* fb_vec = hello_message_pointer->input_sharing_seed();
  randomness_sharing_seed_promises.at(party_id).set_value(
      std::vector(std::begin(*fb_vec), std::end(*fb_vec)));

  fb_vec = hello_message_pointer->fixed_key_aes_seed();
  fixed_key_aes_seed_promises.at(party_id).set_value(
      std::vector(std::begin(*fb_vec), std::end(*fb_vec)));
}

BaseProvider::BaseProvider(communication::CommunicationLayer& communication_layer,
                           std::shared_ptr<Logger> logger)
    : communication_layer_(communication_layer),
      logger_(std::move(logger)),
      number_of_parties_(communication_layer_.GetNumberOfParties()),
      my_id_(communication_layer_.GetMyId()),
      my_randomness_generators_(number_of_parties_),
      their_randomness_generators_(number_of_parties_),
      hello_message_handler_(std::make_shared<HelloMessageHandler>(number_of_parties_, logger_)),
      output_message_handlers_(number_of_parties_),
      setup_ready_(false),
      setup_ready_cond_(std::make_unique<FiberCondition>([this] { return setup_ready_; })) {
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    output_message_handlers_.at(party_id) =
        std::make_shared<OutputMessageHandler>(party_id, nullptr);
  }
  // register handler
  communication_layer_.RegisterMessageHandler([this](auto) { return hello_message_handler_; },
                                              {communication::MessageType::kHelloMessage});
  communication_layer_.RegisterMessageHandler(
      [this](std::size_t party_id) { return output_message_handlers_.at(party_id); },
      {communication::MessageType::kOutputMessage});
}

BaseProvider::~BaseProvider() {
  communication_layer_.DeregisterMessageHandler(
      {communication::MessageType::kHelloMessage, communication::MessageType::kOutputMessage});
}

void BaseProvider::Setup() {
  bool setup_started = execute_setup_flag_.test_and_set();
  if (setup_started) {
    if constexpr (kDebug) {
      if (logger_) {
        logger_->LogDebug("BaseProvider::Setup: waiting for setup being completed");
      }
    }
    setup_ready_cond_->Wait();
    return;
  }
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

  // prepare and send HelloMessage
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto msg_builder = communication::BuildHelloMessage(
        my_id_, party_id, number_of_parties_, &my_seeds.at(party_id), &aes_fixed_key_,
        /* TODO: configuration_->GetOnlineAfterSetup()*/ true, kVersion);
    communication_layer_.SendMessage(party_id, std::move(msg_builder));
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
    auto aes_key = hello_message_handler_->fixed_key_aes_seed_futures.at(party_id).get();
    // add received share to the fixed aes key
    std::transform(std::begin(aes_fixed_key_), std::end(aes_fixed_key_), std::begin(aes_key),
                   std::begin(aes_fixed_key_), [](auto a, auto b) { return a ^ b; });
    auto their_seed = hello_message_handler_->randomness_sharing_seed_futures.at(party_id).get();
    // initialize randomness generator of the other party
    their_randomness_generators_.at(party_id)->Initialize(their_seed.data());
  }
  {
    std::scoped_lock lock(setup_ready_cond_->GetMutex());
    setup_ready_ = true;
  }
  setup_ready_cond_->NotifyAll();
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("BaseProvider::Setup: setup completed");
    }
  }
}

void BaseProvider::WaitForSetup() const { setup_ready_cond_->Wait(); }

std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> BaseProvider::RegisterForOutputMessages(
    std::size_t gate_id) {
  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> futures(number_of_parties_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) =
        output_message_handlers_.at(party_id)->register_for_output_message(gate_id);
  }
  return futures;
}

}  // namespace encrypto::motion
