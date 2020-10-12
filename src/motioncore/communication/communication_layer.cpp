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
#include "message_handler.h"
#include "sync_handler.h"
#include "tcp_transport.h"
#include "utility/constants.h"
#include "utility/logger.h"
#include "utility/synchronized_queue.h"
#include "utility/thread.h"

namespace encrypto::motion::communication {

struct CommunicationLayer::CommunicationLayerImplementation {
  CommunicationLayerImplementation(std::size_t my_id,
                                   std::vector<std::unique_ptr<Transport>>&& transports,
                                   std::shared_ptr<Logger> logger);
  // run in a thread for each party
  void ReceiveTask(std::size_t party_id);
  void SendTask(std::size_t party_id);

  // setup threads and data structures
  void initialize(std::size_t my_id, std::size_t number_of_parties);
  void SendTerminationMessages();
  void Shutdown();

  std::size_t my_id_;
  std::size_t number_of_parties_;

  std::promise<void> start_promise_;
  std::shared_future<void> start_sfuture_;
  std::atomic<bool> continue_communication_ = true;

  std::vector<std::unique_ptr<Transport>> transports_;

  // message type
  using message_t =
      std::variant<std::vector<std::uint8_t>, std::shared_ptr<const std::vector<std::uint8_t>>>;

  std::vector<SynchronizedFiberQueue<message_t>> send_queues_;
  std::vector<std::thread> receive_threads_;
  std::vector<std::thread> send_threads_;

  using MessageHandlerMap = std::unordered_map<MessageType, std::shared_ptr<MessageHandler>>;
  std::shared_mutex message_handlers_mutex_;
  std::vector<MessageHandlerMap> message_handlers_;
  std::vector<std::shared_ptr<MessageHandler>> fallback_message_handlers_;

  std::shared_ptr<SynchronizationHandler> sync_handler_;

  std::shared_ptr<Logger> logger_;
};

CommunicationLayer::CommunicationLayerImplementation::CommunicationLayerImplementation(
    std::size_t my_id, std::vector<std::unique_ptr<Transport>>&& transports,
    std::shared_ptr<Logger> logger)
    : my_id_(my_id),
      number_of_parties_(transports.size()),
      start_sfuture_(start_promise_.get_future().share()),
      transports_(std::move(transports)),
      send_queues_(number_of_parties_),
      message_handlers_(number_of_parties_),
      fallback_message_handlers_(number_of_parties_),
      sync_handler_(std::make_shared<SynchronizationHandler>(my_id_, number_of_parties_, logger)),
      logger_(std::move(logger)) {
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id) {
      receive_threads_.emplace_back();
      send_threads_.emplace_back();
      continue;
    }
    receive_threads_.emplace_back([this, party_id] { ReceiveTask(party_id); });
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
      if (message.index() == 0) {
        // std::vector<std::uint8_t>
        transport.SendMessage(std::get<0>(message));
      } else if (message.index() == 1) {
        // std::shared_ptr<const std::vector<std::uint8_t>>
        transport.SendMessage(*std::get<1>(message));
      }
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

void CommunicationLayer::CommunicationLayerImplementation::ReceiveTask(std::size_t party_id) {
  auto& transport = *transports_.at(party_id);
  auto& handler_map = message_handlers_.at(party_id);

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
      auto fallback_handler = fallback_message_handlers_.at(party_id);
      if (fallback_handler) {
        fallback_handler->ReceivedMessage(party_id, std::move(raw_message));
      }
      continue;
    }

    // XXX: maybe use a separate thread for this
    auto message = GetMessage(raw_message.data());

    auto message_type = message->message_type();
    if constexpr (kDebug) {
      if (logger_) {
        logger_->LogDebug(fmt::format("received message of type {} from party {}",
                                      EnumNameMessageType(message_type), party_id));
      }
    }
    if (message_type == MessageType::kTerminationMessage) {
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("received termination message from party {}", party_id));
        }
      }
      break;
    }
    std::shared_lock lock(message_handlers_mutex_);
    auto iterator = handler_map.find(message_type);
    if (iterator != handler_map.end()) {
      iterator->second->ReceivedMessage(party_id, std::move(raw_message));
    } else {
      auto fallback_handler = fallback_message_handlers_.at(party_id);
      if (fallback_handler) {
        fallback_handler->ReceivedMessage(party_id, std::move(raw_message));
      }
      if (logger_) {
        logger_->LogError(fmt::format("dropping message of type {} from party {}",
                                      EnumNameMessageType(message_type), party_id));
      }
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
      implementation_(
          std::make_unique<CommunicationLayerImplementation>(my_id, std::move(transports), logger)),
      is_started_(false),
      is_shutdown_(false),
      logger_(std::move(logger)) {
  if (number_of_parties_ <= 1) {
    throw std::invalid_argument(
        fmt::format("speficied invalid number of parties: {} <= 1", number_of_parties_));
  }
  if (my_id >= number_of_parties_) {
    throw std::invalid_argument(
        fmt::format("speficied invalid party id: {} >= {}", my_id, number_of_parties_));
  }
  RegisterMessageHandler([this](auto) { return implementation_->sync_handler_; },
                         {MessageType::kSynchronizationMessage});
}

CommunicationLayer::~CommunicationLayer() {
  DeregisterMessageHandler({MessageType::kSynchronizationMessage});
  Shutdown();
}

void CommunicationLayer::Start() {
  if (is_started_) {
    return;
  }
  implementation_->start_promise_.set_value();
  if constexpr (kDebug) {
    if (logger_) {
      for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
        if (party_id == my_id_) {
          continue;
        }
        for (auto& [type, h] : implementation_->message_handlers_.at(party_id)) {
          logger_->LogDebug(fmt::format("message_handler installed for party {}, type {}", party_id,
                                        EnumNameMessageType(type)));
        }
      }
    }
  }
  is_started_ = true;
}

void CommunicationLayer::Synchronize() {
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("start synchronization");
    }
  }
  auto& synchronization_handler = *implementation_->sync_handler_;
  // synchronize s.t. this method cannot be executed simultaneously
  std::scoped_lock lock(synchronization_handler.GetMutex());
  // increment counter
  std::uint64_t new_synchronization_state =
      synchronization_handler.IncrementMySynchronizationState();
  // broadcast sync message with counter value
  {
    const std::vector<std::uint8_t> v(reinterpret_cast<std::uint8_t*>(&new_synchronization_state),
                                      reinterpret_cast<std::uint8_t*>(&new_synchronization_state) +
                                          sizeof(new_synchronization_state));
    auto message_builder = BuildMessage(MessageType::kSynchronizationMessage, &v);
    BroadcastMessage(std::move(message_builder));
  }
  // wait for N-1 sync messages with at least the same value
  synchronization_handler.Wait();
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("finished synchronization");
    }
  }
}

void CommunicationLayer::SendMessage(std::size_t party_id, std::vector<std::uint8_t>&& message) {
  implementation_->send_queues_.at(party_id).enqueue(std::move(message));
}

void CommunicationLayer::SendMessage(std::size_t party_id,
                                     const std::vector<std::uint8_t>& message) {
  implementation_->send_queues_.at(party_id).enqueue(message);
}

void CommunicationLayer::SendMessage(std::size_t party_id,
                                     std::shared_ptr<const std::vector<std::uint8_t>> message) {
  implementation_->send_queues_.at(party_id).enqueue(std::move(message));
}

void CommunicationLayer::SendMessage(std::size_t party_id,
                                     flatbuffers::FlatBufferBuilder&& message_builder) {
  auto message_detached = message_builder.Release();
  auto message_buffer = message_detached.data();
  SendMessage(party_id,
              std::vector<std::uint8_t>(message_buffer, message_buffer + message_detached.size()));
}

void CommunicationLayer::BroadcastMessage(std::vector<std::uint8_t>&& message) {
  if (number_of_parties_ == 2) {
    SendMessage(1 - my_id_, std::move(message));
    return;
  }
  BroadcastMessage(std::make_shared<std::vector<std::uint8_t>>(std::move(message)));
}

// TODO: prevent unnecessary copies
void CommunicationLayer::BroadcastMessage(const std::vector<std::uint8_t>& message) {
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    implementation_->send_queues_.at(party_id).enqueue(message);
  }
}

void CommunicationLayer::BroadcastMessage(
    std::shared_ptr<const std::vector<std::uint8_t>> message) {
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    implementation_->send_queues_.at(party_id).enqueue(message);
  }
}

void CommunicationLayer::BroadcastMessage(flatbuffers::FlatBufferBuilder&& message_builder) {
  auto message_detached = message_builder.Release();
  auto message_buffer = message_detached.data();
  if (number_of_parties_ == 2) {
    SendMessage(1 - my_id_, std::vector<std::uint8_t>(message_buffer,
                                                      message_buffer + message_detached.size()));
    return;
  }
  BroadcastMessage(std::make_shared<std::vector<std::uint8_t>>(
      message_buffer, message_buffer + message_detached.size()));
}

void CommunicationLayer::RegisterMessageHandler(MessageHandlerFunction handler_factory,
                                                const std::vector<MessageType>& message_types) {
  std::scoped_lock lock(implementation_->message_handlers_mutex_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& map = implementation_->message_handlers_.at(party_id);
    auto handler = handler_factory(party_id);
    for (auto type : message_types) {
      map.emplace(type, handler);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("registered handler for messages of type {} from party {}",
                                        EnumNameMessageType(type), party_id));
        }
      }
    }
  }
}

void CommunicationLayer::DeregisterMessageHandler(const std::vector<MessageType>& message_types) {
  std::scoped_lock lock(implementation_->message_handlers_mutex_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& map = implementation_->message_handlers_.at(party_id);
    for (auto type : message_types) {
      map.erase(type);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(
              fmt::format("deregistered handler for messages of type {} from party {}",
                          EnumNameMessageType(type), party_id));
        }
      }
    }
  }
}

MessageHandler& CommunicationLayer::GetMessageHandler(std::size_t party_id,
                                                      MessageType message_type) {
  if (party_id == my_id_ || party_id >= number_of_parties_) {
    throw std::invalid_argument(fmt::format("invalid party_id {} specified", party_id));
  }
  std::scoped_lock lock(implementation_->message_handlers_mutex_);
  const auto& map = implementation_->message_handlers_.at(party_id);
  auto iterator = map.find(message_type);
  if (iterator == map.end()) {
    throw std::logic_error(fmt::format(
        "no message_handler registered for message_type {} and party {}", message_type, party_id));
  }
  return *iterator->second;
}

void CommunicationLayer::RegisterFallbackMessageHandler(MessageHandlerFunction handler_factory) {
  auto& fallback_handlers = implementation_->fallback_message_handlers_;
  fallback_handlers.resize(number_of_parties_);
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    fallback_handlers.at(party_id) = handler_factory(party_id);
  }
}

MessageHandler& CommunicationLayer::GetFallbackMessageHandler(std::size_t party_id) {
  if (party_id == my_id_ || party_id >= number_of_parties_) {
    throw std::invalid_argument(fmt::format("invalid party_id {} specified", party_id));
  }
  return *implementation_->fallback_message_handlers_.at(party_id);
}

void CommunicationLayer::Shutdown() {
  if (is_shutdown_) {
    return;
  }
  auto message_builder = BuildMessage(MessageType::kTerminationMessage, nullptr);
  BroadcastMessage(std::move(message_builder));
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
