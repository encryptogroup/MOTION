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

namespace MOTION::Communication {

struct CommunicationLayer::CommunicationLayerImpl {
  CommunicationLayerImpl(std::size_t my_id, std::vector<std::unique_ptr<Transport>>&& transports,
                         std::shared_ptr<Logger> logger);
  // run in a thread for each party
  void receive_task(std::size_t party_id);
  void send_task(std::size_t party_id);

  // setup threads and data structures
  void initialize(std::size_t my_id, std::size_t num_parties);
  void send_termination_messages();
  void shutdown();

  std::size_t my_id_;
  std::size_t num_parties_;

  std::promise<void> start_promise_;
  std::shared_future<void> start_sfuture_;
  std::atomic<bool> continue_communication_ = true;

  std::vector<std::unique_ptr<Transport>> transports_;

  // message type
  using message_t =
      std::variant<std::vector<std::uint8_t>, std::shared_ptr<const std::vector<std::uint8_t>>>;

  std::vector<ENCRYPTO::SynchronizedFiberQueue<message_t>> send_queues_;
  std::vector<std::thread> receive_threads_;
  std::vector<std::thread> send_threads_;

  using MessageHandlerMap = std::unordered_map<MessageType, std::shared_ptr<MessageHandler>>;
  std::shared_mutex message_handlers_mutex_;
  std::vector<MessageHandlerMap> message_handlers_;
  std::vector<std::shared_ptr<MessageHandler>> fallback_message_handlers_;

  std::shared_ptr<SyncHandler> sync_handler_;

  std::shared_ptr<Logger> logger_;
};

CommunicationLayer::CommunicationLayerImpl::CommunicationLayerImpl(
    std::size_t my_id, std::vector<std::unique_ptr<Transport>>&& transports,
    std::shared_ptr<Logger> logger)
    : my_id_(my_id),
      num_parties_(transports.size()),
      start_sfuture_(start_promise_.get_future().share()),
      transports_(std::move(transports)),
      send_queues_(num_parties_),
      message_handlers_(num_parties_),
      fallback_message_handlers_(num_parties_),
      sync_handler_(std::make_shared<SyncHandler>(my_id_, num_parties_, logger)),
      logger_(std::move(logger)) {
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id) {
      receive_threads_.emplace_back();
      send_threads_.emplace_back();
      continue;
    }
    receive_threads_.emplace_back([this, party_id] { receive_task(party_id); });
    send_threads_.emplace_back([this, party_id] { send_task(party_id); });

    ENCRYPTO::thread_set_name(receive_threads_.at(party_id),
                              fmt::format("recv-{}<->{}", my_id_, party_id));
    ENCRYPTO::thread_set_name(send_threads_.at(party_id),
                              fmt::format("send-{}<->{}", my_id_, party_id));
  }
}

void CommunicationLayer::CommunicationLayerImpl::send_task(std::size_t party_id) {
  auto& queue = send_queues_.at(party_id);
  auto& transport = *transports_.at(party_id);

  auto my_start_sfuture = start_sfuture_;
  my_start_sfuture.get();

  while (!queue.closed_and_empty()) {
    auto tmp_queue = queue.batch_dequeue();
    if (!tmp_queue.has_value()) {
      assert(queue.closed());
      break;
    }
    while (!tmp_queue->empty()) {
      auto& message = tmp_queue->front();
      if (message.index() == 0) {
        // std::vector<std::uint8_t>
        transport.send_message(std::get<0>(message));
      } else if (message.index() == 1) {
        // std::shared_ptr<const std::vector<std::uint8_t>>
        transport.send_message(*std::get<1>(message));
      }
      tmp_queue->pop();
      if (logger_) {
        logger_->LogDebug(fmt::format("Sent message to party {}", party_id));
      }
    }
  }

  transport.shutdown_send();

  if (logger_) {
    logger_->LogDebug(fmt::format("send_task finished for party {}", party_id));
  }
}

void CommunicationLayer::CommunicationLayerImpl::receive_task(std::size_t party_id) {
  auto& transport = *transports_.at(party_id);
  auto& handler_map = message_handlers_.at(party_id);

  auto my_start_sfuture = start_sfuture_;
  my_start_sfuture.get();

  while (continue_communication_) {
    std::optional<std::vector<std::uint8_t>> raw_message_opt;
    try {
      raw_message_opt = transport.receive_message();
    } catch (std::runtime_error& e) {
      if (logger_) {
        logger_->LogError(
            fmt::format("receive_message failed for party {}: {}", party_id, e.what()));
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
      auto fbh = fallback_message_handlers_.at(party_id);
      if (fbh) {
        fbh->received_message(party_id, std::move(raw_message));
      }
      continue;
    }

    // XXX: maybe use a separate thread for this
    auto message = GetMessage(raw_message.data());

    auto message_type = message->message_type();
    if constexpr (MOTION_DEBUG) {
      if (logger_) {
        logger_->LogDebug(
            fmt::format("received message of {} from party {}", to_string(message_type), party_id));
      }
    }
    if (message_type == MessageType::TerminationMessage) {
      if constexpr (MOTION_DEBUG) {
        if (logger_) {
          logger_->LogDebug(fmt::format("received termination message from party {}", party_id));
        }
      }
      break;
    }
    std::shared_lock lock(message_handlers_mutex_);
    auto it = handler_map.find(message_type);
    if (it != handler_map.end()) {
      it->second->received_message(party_id, std::move(raw_message));
    } else {
      auto fbh = fallback_message_handlers_.at(party_id);
      if (fbh) {
        fbh->received_message(party_id, std::move(raw_message));
      }
      if (logger_) {
        logger_->LogError(
            fmt::format("dropping message of type {} from party {}", message_type, party_id));
      }
    }
  }

  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      logger_->LogDebug(fmt::format("receive_task finished for party {}", party_id));
    }
  }
}

void CommunicationLayer::CommunicationLayerImpl::shutdown() {
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    send_queues_.at(party_id).close();
  }
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    send_threads_.at(party_id).join();
    receive_threads_.at(party_id).join();
    transports_.at(party_id)->shutdown();
  }
}

CommunicationLayer::CommunicationLayer(std::size_t my_id,
                                       std::vector<std::unique_ptr<Transport>>&& transports)
    : CommunicationLayer(my_id, std::move(transports), nullptr) {}

CommunicationLayer::CommunicationLayer(std::size_t my_id,
                                       std::vector<std::unique_ptr<Transport>>&& transports,
                                       std::shared_ptr<Logger> logger)
    : my_id_(my_id),
      num_parties_(transports.size()),
      impl_(std::make_unique<CommunicationLayerImpl>(my_id, std::move(transports), logger)),
      is_started_(false),
      is_shutdown_(false),
      logger_(std::move(logger)) {
  if (num_parties_ <= 1) {
    throw std::invalid_argument(
        fmt::format("speficied invalid number of parties: {} <= 1", num_parties_));
  }
  if (my_id >= num_parties_) {
    throw std::invalid_argument(
        fmt::format("speficied invalid party id: {} >= {}", my_id, num_parties_));
  }
  register_message_handler([this](auto) { return impl_->sync_handler_; },
                           {MessageType::SynchronizationMessage});
}

CommunicationLayer::~CommunicationLayer() {
  deregister_message_handler({MessageType::SynchronizationMessage});
  shutdown();
}

void CommunicationLayer::start() {
  if (is_started_) {
    return;
  }
  impl_->start_promise_.set_value();
  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
        if (party_id == my_id_) {
          continue;
        }
        for (auto& [type, h] : impl_->message_handlers_.at(party_id)) {
          logger_->LogDebug(fmt::format("message_handler installed for party {}, type {}", party_id,
                                        to_string(type)));
        }
      }
    }
  }
  is_started_ = true;
}

void CommunicationLayer::sync() {
  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      logger_->LogDebug("start synchronization");
    }
  }
  auto& sync_handler = *impl_->sync_handler_;
  // synchronize s.t. this method cannot be executed simultaneously
  std::scoped_lock lock(sync_handler.get_mutex());
  // increment counter
  std::uint64_t new_sync_state = sync_handler.increment_my_sync_state();
  // broadcast sync message with counter value
  {
    const std::vector<std::uint8_t> v(
        reinterpret_cast<std::uint8_t*>(&new_sync_state),
        reinterpret_cast<std::uint8_t*>(&new_sync_state) + sizeof(new_sync_state));
    auto message_builder = BuildMessage(MessageType::SynchronizationMessage, &v);
    broadcast_message(std::move(message_builder));
  }
  // wait for N-1 sync messages with at least the same value
  sync_handler.wait();
  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      logger_->LogDebug("finished synchronization");
    }
  }
}

void CommunicationLayer::send_message(std::size_t party_id, std::vector<std::uint8_t>&& message) {
  impl_->send_queues_.at(party_id).enqueue(std::move(message));
}

void CommunicationLayer::send_message(std::size_t party_id,
                                      const std::vector<std::uint8_t>& message) {
  impl_->send_queues_.at(party_id).enqueue(message);
}

void CommunicationLayer::send_message(std::size_t party_id,
                                      std::shared_ptr<const std::vector<std::uint8_t>> message) {
  impl_->send_queues_.at(party_id).enqueue(std::move(message));
}

void CommunicationLayer::send_message(std::size_t party_id,
                                      flatbuffers::FlatBufferBuilder&& message_builder) {
  auto message_detached = message_builder.Release();
  auto message_buffer = message_detached.data();
  send_message(party_id,
               std::vector<std::uint8_t>(message_buffer, message_buffer + message_detached.size()));
}

void CommunicationLayer::broadcast_message(std::vector<std::uint8_t>&& message) {
  if (num_parties_ == 2) {
    send_message(1 - my_id_, std::move(message));
    return;
  }
  broadcast_message(std::make_shared<std::vector<std::uint8_t>>(std::move(message)));
}

// TODO: prevent unnecessary copies
void CommunicationLayer::broadcast_message(const std::vector<std::uint8_t>& message) {
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    impl_->send_queues_.at(party_id).enqueue(message);
  }
}

void CommunicationLayer::broadcast_message(
    std::shared_ptr<const std::vector<std::uint8_t>> message) {
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    impl_->send_queues_.at(party_id).enqueue(message);
  }
}

void CommunicationLayer::broadcast_message(flatbuffers::FlatBufferBuilder&& message_builder) {
  auto message_detached = message_builder.Release();
  auto message_buffer = message_detached.data();
  if (num_parties_ == 2) {
    send_message(1 - my_id_, std::vector<std::uint8_t>(message_buffer,
                                                       message_buffer + message_detached.size()));
    return;
  }
  broadcast_message(std::make_shared<std::vector<std::uint8_t>>(
      message_buffer, message_buffer + message_detached.size()));
}

void CommunicationLayer::register_message_handler(message_handler_f handler_factory,
                                                  const std::vector<MessageType>& message_types) {
  std::scoped_lock lock(impl_->message_handlers_mutex_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& map = impl_->message_handlers_.at(party_id);
    auto handler = handler_factory(party_id);
    for (auto type : message_types) {
      map.emplace(type, handler);
      if constexpr (MOTION_DEBUG) {
        if (logger_) {
          logger_->LogDebug(fmt::format("registered handler for messages of type {} from party {}",
                                        to_string(type), party_id));
        }
      }
    }
  }
}

void CommunicationLayer::deregister_message_handler(const std::vector<MessageType>& message_types) {
  std::scoped_lock lock(impl_->message_handlers_mutex_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& map = impl_->message_handlers_.at(party_id);
    for (auto type : message_types) {
      map.erase(type);
      if constexpr (MOTION_DEBUG) {
        if (logger_) {
          logger_->LogDebug(fmt::format(
              "deregistered handler for messages of type {} from party {}", type, party_id));
        }
      }
    }
  }
}
MessageHandler& CommunicationLayer::get_message_handler(std::size_t party_id,
                                                        MessageType message_type) {
  if (party_id == my_id_ || party_id >= num_parties_) {
    throw std::invalid_argument(fmt::format("invalid party_id {} specified", party_id));
  }
  std::scoped_lock lock(impl_->message_handlers_mutex_);
  const auto& map = impl_->message_handlers_.at(party_id);
  auto it = map.find(message_type);
  if (it == map.end()) {
    throw std::logic_error(fmt::format(
        "no message_handler registered for message_type {} and party {}", message_type, party_id));
  }
  return *it->second;
}

void CommunicationLayer::register_fallback_message_handler(message_handler_f handler_factory) {
  auto& fbhs = impl_->fallback_message_handlers_;
  fbhs.resize(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    fbhs.at(party_id) = handler_factory(party_id);
  }
}

MessageHandler& CommunicationLayer::get_fallback_message_handler(std::size_t party_id) {
  if (party_id == my_id_ || party_id >= num_parties_) {
    throw std::invalid_argument(fmt::format("invalid party_id {} specified", party_id));
  }
  return *impl_->fallback_message_handlers_.at(party_id);
}

void CommunicationLayer::shutdown() {
  if (is_shutdown_) {
    return;
  }
  auto message_builder = BuildMessage(MessageType::TerminationMessage, nullptr);
  broadcast_message(std::move(message_builder));
  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      logger_->LogDebug("broadcasted termination messages");
    }
  }
  impl_->shutdown();
  is_shutdown_ = true;
}

std::vector<TransportStatistics> CommunicationLayer::get_transport_statistics() const noexcept {
  std::vector<TransportStatistics> stats;
  stats.reserve(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    stats.emplace_back(impl_->transports_.at(party_id)->get_stats());
  }
  return stats;
}

void CommunicationLayer::set_logger(std::shared_ptr<Logger> logger) {
  if (is_started_) {
    throw std::logic_error(
        "changing the logger is not allowed after the CommunicationLayer has been started");
  }
  logger_ = logger;
  impl_->logger_ = logger;
}

std::vector<std::unique_ptr<CommunicationLayer>> make_dummy_communication_layers(
    std::size_t num_parties) {
  std::vector<std::vector<std::unique_ptr<Transport>>> transports;
  transports.reserve(num_parties);
  std::generate_n(std::back_inserter(transports), num_parties,
                  [num_parties] { return std::vector<std::unique_ptr<Transport>>(num_parties); });
  for (std::size_t party_i = 0; party_i < num_parties - 1; ++party_i) {
    for (std::size_t party_j = party_i + 1; party_j < num_parties; ++party_j) {
      auto [trans_ij, trans_ji] = DummyTransport::make_transport_pair();
      transports.at(party_i).at(party_j) = std::move(trans_ij);
      transports.at(party_j).at(party_i) = std::move(trans_ji);
    }
  }
  std::vector<std::unique_ptr<CommunicationLayer>> comm_layers;
  comm_layers.reserve(num_parties);
  for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
    comm_layers.emplace_back(
        std::make_unique<CommunicationLayer>(party_id, std::move(transports.at(party_id))));
  }
  return comm_layers;
}

std::vector<std::unique_ptr<CommunicationLayer>> make_local_tcp_communication_layers(
    std::size_t num_parties, bool ipv6) {
  const auto localhost = ipv6 ? "::1" : "127.0.0.1";
  tcp_parties_config config;
  config.reserve(num_parties);
  for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
    config.push_back({localhost, 10000 + party_id});
  }
  std::vector<std::future<std::vector<std::unique_ptr<Transport>>>> futs;
  for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
    futs.emplace_back(std::async(std::launch::async, [party_id, &config] {
      TCPSetupHelper helper(party_id, config);
      return helper.setup_connections();
    }));
  }
  std::vector<std::unique_ptr<CommunicationLayer>> comm_layers;
  comm_layers.reserve(num_parties);
  for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
    auto transports = futs.at(party_id).get();
    comm_layers.emplace_back(std::make_unique<CommunicationLayer>(party_id, std::move(transports)));
  }
  return comm_layers;
}

}  // namespace MOTION::Communication
