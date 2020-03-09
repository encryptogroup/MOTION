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
#include "communication/message_handler.h"
#include "output_message_handler.h"
#include "sharing_randomness_generator.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"
#include "utility/reusable_future.h"

namespace MOTION::Crypto {

// Handler for messages of type HelloMessage
struct HelloMessageHandler : public Communication::MessageHandler {
  // Create a handler object for a given party
  HelloMessageHandler(std::size_t num_parties, std::shared_ptr<Logger> logger)
      : logger_(logger),
        fixed_key_aes_seed_promises_(num_parties),
        randomness_sharing_seed_promises_(num_parties) {
    std::transform(std::begin(fixed_key_aes_seed_promises_), std::end(fixed_key_aes_seed_promises_),
                   std::back_inserter(fixed_key_aes_seed_futures_),
                   [](auto& p) { return p.get_future(); });
    std::transform(std::begin(randomness_sharing_seed_promises_),
                   std::end(randomness_sharing_seed_promises_),
                   std::back_inserter(randomness_sharing_seed_futures_),
                   [](auto& p) { return p.get_future(); });
  }

  // Method which is called on received messages.
  void received_message(std::size_t party_id, std::vector<std::uint8_t>&& message) override;

  ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>> get_randomness_sharing_seed_future();

  std::shared_ptr<Logger> logger_;

  std::vector<ENCRYPTO::ReusablePromise<std::vector<std::uint8_t>>> fixed_key_aes_seed_promises_;
  std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>> fixed_key_aes_seed_futures_;

  std::vector<ENCRYPTO::ReusablePromise<std::vector<std::uint8_t>>>
      randomness_sharing_seed_promises_;
  std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>> randomness_sharing_seed_futures_;
};

void HelloMessageHandler::received_message(std::size_t party_id,
                                           std::vector<std::uint8_t>&& hello_message) {
  assert(!hello_message.empty());
  auto message = Communication::GetMessage(reinterpret_cast<std::uint8_t*>(hello_message.data()));
  auto hello_message_ptr = Communication::GetHelloMessage(message->payload()->data());

  auto* fb_vec = hello_message_ptr->input_sharing_seed();
  randomness_sharing_seed_promises_.at(party_id).set_value(
      std::vector(std::begin(*fb_vec), std::end(*fb_vec)));

  fb_vec = hello_message_ptr->fixed_key_aes_seed();
  fixed_key_aes_seed_promises_.at(party_id).set_value(
      std::vector(std::begin(*fb_vec), std::end(*fb_vec)));
}

MotionBaseProvider::MotionBaseProvider(Communication::CommunicationLayer& communication_layer,
                                       std::shared_ptr<Logger> logger)
    : communication_layer_(communication_layer),
      logger_(std::move(logger)),
      num_parties_(communication_layer_.get_num_parties()),
      my_id_(communication_layer_.get_my_id()),
      my_randomness_generators_(num_parties_),
      their_randomness_generators_(num_parties_),
      hello_message_handler_(std::make_shared<HelloMessageHandler>(num_parties_, logger_)),
      output_message_handlers_(num_parties_),
      setup_ready_(false),
      setup_ready_cond_(
          std::make_unique<ENCRYPTO::FiberCondition>([this] { return setup_ready_; })) {
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    output_message_handlers_.at(party_id) =
        std::make_shared<OutputMessageHandler>(party_id, nullptr);
  }
  // register handler
  communication_layer_.register_message_handler([this](auto) { return hello_message_handler_; },
                                                {Communication::MessageType::HelloMessage});
  communication_layer_.register_message_handler(
      [this](std::size_t party_id) { return output_message_handlers_.at(party_id); },
      {Communication::MessageType::OutputMessage});
}

MotionBaseProvider::~MotionBaseProvider() {
  communication_layer_.deregister_message_handler(
      {Communication::MessageType::HelloMessage, Communication::MessageType::OutputMessage});
}

void MotionBaseProvider::setup() {
  bool setup_started = execute_setup_flag_.test_and_set();
  if (setup_started) {
    if constexpr (MOTION_DEBUG) {
      if (logger_) {
        logger_->LogDebug("MotionBaseProvider::setup: waiting for setup being completed");
      }
    }
    setup_ready_cond_->Wait();
    return;
  }
  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      logger_->LogDebug("MotionBaseProvider::setup: running setup");
    }
  }

  // generate share, broadcast, wait for messages, xor
  aes_fixed_key_ = Helpers::RandomVector<std::uint8_t>(16);
  std::vector<std::vector<std::uint8_t>> my_seeds;
  std::generate_n(std::back_inserter(my_seeds), num_parties_,
                  [] { return Helpers::RandomVector<std::uint8_t>(32); });

  // prepare and send HelloMessage
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto msg_builder = Communication::BuildHelloMessage(
        my_id_, party_id, num_parties_, &my_seeds.at(party_id), &aes_fixed_key_,
        /* TODO: config_->GetOnlineAfterSetup()*/ true, MOTION_VERSION);
    communication_layer_.send_message(party_id, std::move(msg_builder));
  }
  // initialize my randomness generators
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    my_randomness_generators_.at(party_id) = std::make_unique<SharingRandomnessGenerator>(party_id);
    my_randomness_generators_.at(party_id)->Initialize(
        reinterpret_cast<std::uint8_t*>(my_seeds.at(party_id).data()));
    their_randomness_generators_.at(party_id) =
        std::make_unique<SharingRandomnessGenerator>(party_id);
  }
  // receive HelloMessages from other and initialize
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto aes_key = hello_message_handler_->fixed_key_aes_seed_futures_.at(party_id).get();
    // add received share to the fixed aes key
    std::transform(std::begin(aes_fixed_key_), std::end(aes_fixed_key_), std::begin(aes_key),
                   std::begin(aes_fixed_key_), [](auto a, auto b) { return a ^ b; });
    auto their_seed = hello_message_handler_->randomness_sharing_seed_futures_.at(party_id).get();
    // initialize randomness generator of the other party
    their_randomness_generators_.at(party_id)->Initialize(their_seed.data());
  }
  {
    std::scoped_lock lock(setup_ready_cond_->GetMutex());
    setup_ready_ = true;
  }
  setup_ready_cond_->NotifyAll();
  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      logger_->LogDebug("MotionBaseProvider::setup: setup completed");
    }
  }
}

void MotionBaseProvider::wait_for_setup() const { setup_ready_cond_->Wait(); }

std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>>
MotionBaseProvider::register_for_output_messages(std::size_t gate_id) {
  std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>> futures(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) =
        output_message_handlers_.at(party_id)->register_for_output_message(gate_id);
  }
  return futures;
}

}  // namespace MOTION::Crypto
