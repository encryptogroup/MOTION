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

#include "communication_layer.h"

#include <cstdint>
#include <functional>
#include <limits>
#include <shared_mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <variant>

#include <flatbuffers/flatbuffers.h>
#include <fmt/format.h>

#include "dummy_transport.h"
#include "message.h"
#include "message_manager.h"
#include "tcp_transport.h"
#include "utility/constants.h"
#include "utility/logger.h"
#include "utility/synchronized_queue.h"
#include "utility/thread.h"

namespace encrypto::motion::communication {

struct CommunicationLayer::CommunicationLayerImplementation {
  CommunicationLayerImplementation(std::size_t my_id,
                                   std::vector<std::unique_ptr<Transport>>&& transports,
                                   MessageManager& message_manager, std::shared_ptr<Logger> logger);
  // run in a thread for each party
  void ReceiveTask(std::size_t party_id, MessageManager& message_manager);
  void SendTask(std::size_t party_id);

  // setup threads and data structures
  void Initialize(std::size_t my_id, std::size_t number_of_parties);
  void SendTerminationMessages();
  void Shutdown();

  std::size_t my_id_;
  std::size_t number_of_parties_;

  std::promise<void> start_promise_;
  std::shared_future<void> start_sfuture_;
  std::atomic<bool> continue_communication_ = true;

  std::vector<std::unique_ptr<Transport>> transports_;

  // message type
  using message_t = std::shared_ptr<flatbuffers::DetachedBuffer>;

  std::vector<SynchronizedFiberQueue<message_t>> send_queues_;
  std::vector<std::thread> receive_threads_;
  std::vector<std::thread> send_threads_;

  std::shared_ptr<Logger> logger_;
};

CommunicationLayer::CommunicationLayerImplementation::CommunicationLayerImplementation(
    std::size_t my_id, std::vector<std::unique_ptr<Transport>>&& transports,
    MessageManager& message_manager, std::shared_ptr<Logger> logger)
    : my_id_(my_id),
      number_of_parties_(transports.size()),
      start_sfuture_(start_promise_.get_future().share()),
      transports_(std::move(transports)),
      send_queues_(number_of_parties_),
      logger_(std::move(logger)) {
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id) {
      receive_threads_.emplace_back();
      send_threads_.emplace_back();
      continue;
    }
    receive_threads_.emplace_back(
        [this, &message_manager, party_id] { ReceiveTask(party_id, message_manager); });
    send_threads_.emplace_back([this, party_id] { SendTask(party_id); });

    ThreadSetName(receive_threads_.at(party_id), fmt::format("recv-{}<->{}", my_id_, party_id));
    ThreadSetName(send_threads_.at(party_id), fmt::format("send-{}<->{}", my_id_, party_id));
  }
}

void CommunicationLayer::CommunicationLayerImplementation::SendTask(std::size_t party_id) {
  auto& queue = send_queues_.at(party_id);
  auto& transport = *transports_.at(party_id);

  auto my_start_sfuture = start_sfuture_;
  my_start_sfuture.get();

  while (!queue.IsClosedAndEmpty()) {
    auto tmp_queue = queue.BatchDequeue();
    if (!tmp_queue.has_value()) {
      assert(queue.IsClosed());
      break;
    }
    while (!tmp_queue->empty()) {
      auto& message = tmp_queue->front();
      transport.SendMessage(std::span(message->data(), message->size()));
      tmp_queue->pop();
      if (logger_) {
        logger_->LogDebug(fmt::format("Sent message to party {}", party_id));
      }
    }
  }

  transport.ShutdownSend();

  if (logger_) {
    logger_->LogDebug(fmt::format("SendTask finished for party {}", party_id));
  }
}

void CommunicationLayer::CommunicationLayerImplementation::ReceiveTask(
    std::size_t party_id, MessageManager& message_manager) {
  auto& transport = *transports_.at(party_id);

  auto my_start_sfuture = start_sfuture_;
  my_start_sfuture.get();

  while (continue_communication_) {
    std::optional<std::vector<std::uint8_t>> raw_message_opt;
    try {
      raw_message_opt = transport.ReceiveMessage();
    } catch (std::runtime_error& e) {
      if (logger_) {
        logger_->LogError(
            fmt::format("ReceiveMessage failed for party {}: {}", party_id, e.what()));
      }
      break;
    }
    if (!raw_message_opt.has_value()) {
      // underlying transport was closed unexpectedly
      if (logger_) {
        logger_->LogError(
            fmt::format("underlying transport was closed unexpectedly from party {}", party_id));
      }
      break;
    }
    auto raw_message = std::move(*raw_message_opt);
    flatbuffers::Verifier verifier(reinterpret_cast<std::uint8_t*>(raw_message.data()),
                                   raw_message.size());
    if (!VerifyMessageBuffer(verifier)) {
      if (logger_) {
        logger_->LogError(fmt::format("received corrupt message from party {}", party_id));
      }
      continue;
    }

    // XXX: maybe use a separate thread for this
    auto message = GetMessage(raw_message.data());

    auto message_id = message->message_id();
    auto message_type = message->message_type();
    if constexpr (kDebug) {
      if (logger_) {
        logger_->LogDebug(fmt::format("received message of type {} with id {} from party {}",
                                      EnumNameMessageType(message_type), message_id, party_id));
      }
    }
    if (message_type == MessageType::kTerminationMessage) {
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("received termination message from party {}", party_id));
        }
      }
      break;
    } else if (message_type == MessageType::kSynchronizationMessage) {
      message_manager.GetSyncStates(party_id).enqueue(std::move(raw_message));
    } else {
      assert(!message_manager.GetMessagePromises(party_id).empty());
      assert(message_manager.GetMessagePromises(party_id).contains(message_type));
      assert(message_manager.GetMessagePromises(party_id)[message_type].contains(message_id));
      message_manager.GetMessagePromises(party_id)[message_type][message_id]->set_value(
          std::move(raw_message));
    }
  }

  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("ReceiveTask finished for party {}", party_id));
    }
  }
}

void CommunicationLayer::CommunicationLayerImplementation::Shutdown() {
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    send_queues_.at(party_id).close();
  }
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    send_threads_.at(party_id).join();
    receive_threads_.at(party_id).join();
    transports_.at(party_id)->Shutdown();
  }
}

CommunicationLayer::CommunicationLayer(std::size_t my_id,
                                       std::vector<std::unique_ptr<Transport>>&& transports)
    : CommunicationLayer(my_id, std::move(transports), nullptr) {}

CommunicationLayer::CommunicationLayer(std::size_t my_id,
                                       std::vector<std::unique_ptr<Transport>>&& transports,
                                       std::shared_ptr<Logger> logger)
    : my_id_(my_id),
      number_of_parties_(transports.size()),
      is_started_(false),
      is_shutdown_(false),
      logger_(std::move(logger)),
      message_manager_(std::make_shared<MessageManager>(number_of_parties_, my_id_)) {
  if (number_of_parties_ <= 1) {
    throw std::invalid_argument(
        fmt::format("speficied invalid number of parties: {} <= 1", number_of_parties_));
  }
  if (my_id >= number_of_parties_) {
    throw std::invalid_argument(
        fmt::format("speficied invalid party id: {} >= {}", my_id, number_of_parties_));
  }
  implementation_ = std::make_unique<CommunicationLayerImplementation>(my_id, std::move(transports),
                                                                       *message_manager_, logger);
}

CommunicationLayer::~CommunicationLayer() { Shutdown(); }

void CommunicationLayer::Start() {
  if (is_started_) {
    return;
  }
  implementation_->start_promise_.set_value();
  is_started_ = true;
}

void CommunicationLayer::Synchronize() {
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("start synchronization");
    }
  }
  // broadcast sync message with counter value
  {
    std::span s(reinterpret_cast<const std::uint8_t*>(&sync_state_), sizeof(sync_state_));
    assert(s.size() == 8);
    auto message_builder = BuildMessage(MessageType::kSynchronizationMessage, s);
    BroadcastMessage(message_builder.Release());
  }
  // wait for N-1 sync messages with at least the same value
  for (auto& q : message_manager_->GetSyncStates()) {
    if constexpr (kDebug) {
      auto bytes{*q.dequeue()};
      std::size_t other_state;
      std::copy_n(GetMessage(bytes.data())->payload()->data(), sizeof(other_state),
                  reinterpret_cast<uint8_t*>(&other_state));
      assert(sync_state_ == other_state);
    } else {
      q.dequeue();
    }
  }
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("finished synchronization");
    }
  }
  // increment counter
  ++sync_state_;
}

void CommunicationLayer::SendMessage(std::size_t party_id, flatbuffers::DetachedBuffer&& message) {
  implementation_->send_queues_[party_id].enqueue(
      std::make_shared<flatbuffers::DetachedBuffer>(std::move(message)));
}

void CommunicationLayer::BroadcastMessage(flatbuffers::DetachedBuffer&& message) {
  if (number_of_parties_ == 2) {
    SendMessage(1 - my_id_, std::move(message));
    return;
  }
  auto shared_message = std::make_shared<flatbuffers::DetachedBuffer>(std::move(message));

  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id != my_id_) implementation_->send_queues_[party_id].enqueue(shared_message);
  }
}

void CommunicationLayer::Shutdown() {
  if (is_shutdown_) {
    return;
  }
  auto message_builder = BuildMessage(MessageType::kTerminationMessage);
  BroadcastMessage(message_builder.Release());
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("broadcasted termination messages");
    }
  }
  implementation_->Shutdown();
  is_shutdown_ = true;
}

std::vector<TransportStatistics> CommunicationLayer::GetTransportStatistics() const noexcept {
  std::vector<TransportStatistics> statistics;
  statistics.reserve(number_of_parties_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    statistics.emplace_back(implementation_->transports_.at(party_id)->GetStatistics());
  }
  return statistics;
}

void CommunicationLayer::SetLogger(std::shared_ptr<Logger> logger) {
  if (is_started_) {
    throw std::logic_error(
        "changing the logger is not allowed after the CommunicationLayer has been started");
  }
  logger_ = logger;
  implementation_->logger_ = logger;
}

std::vector<std::unique_ptr<CommunicationLayer>> MakeDummyCommunicationLayers(
    std::size_t number_of_parties) {
  std::vector<std::vector<std::unique_ptr<Transport>>> transports;
  transports.reserve(number_of_parties);
  std::generate_n(std::back_inserter(transports), number_of_parties, [number_of_parties] {
    return std::vector<std::unique_ptr<Transport>>(number_of_parties);
  });
  for (std::size_t party_i = 0; party_i < number_of_parties - 1; ++party_i) {
    for (std::size_t party_j = party_i + 1; party_j < number_of_parties; ++party_j) {
      auto [trans_ij, trans_ji] = DummyTransport::MakeTransportPair();
      transports.at(party_i).at(party_j) = std::move(trans_ij);
      transports.at(party_j).at(party_i) = std::move(trans_ji);
    }
  }
  std::vector<std::unique_ptr<CommunicationLayer>> communication_layers;
  communication_layers.reserve(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    communication_layers.emplace_back(
        std::make_unique<CommunicationLayer>(party_id, std::move(transports.at(party_id))));
  }
  return communication_layers;
}

std::vector<std::unique_ptr<CommunicationLayer>> MakeLocalTcpCommunicationLayers(
    std::size_t number_of_parties, bool ipv6) {
  constexpr uint16_t kPort = 10000;
  const auto localhost = ipv6 ? "::1" : "127.0.0.1";
  TcpPartiesConfiguration configuration;
  configuration.reserve(number_of_parties);
  assert(number_of_parties < std::numeric_limits<uint16_t>::max());
  for (uint16_t party_id = 0; party_id < number_of_parties; ++party_id) {
    configuration.push_back({localhost, kPort + party_id});
  }
  std::vector<std::future<std::vector<std::unique_ptr<Transport>>>> futures;
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, &configuration] {
      TcpSetupHelper helper(party_id, configuration);
      return helper.SetupConnections();
    }));
  }
  std::vector<std::unique_ptr<CommunicationLayer>> communication_layers;
  communication_layers.reserve(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    auto transports = futures.at(party_id).get();
    communication_layers.emplace_back(
        std::make_unique<CommunicationLayer>(party_id, std::move(transports)));
  }
  return communication_layers;
}

}  // namespace encrypto::motion::communication
