#include "communication_context.h"

#include <fmt/format.h>
#include <chrono>
#include <cstdlib>

#include "utility/constants.h"
#include "utility/helpers.h"
#include "utility/random.h"
#include "utility/typedefs.h"

namespace ABYN {

CommunicationContext::CommunicationContext(std::string ip, u16 port,
                                           ABYN::Role role, std::size_t id)
    : data_storage_(id),
      ip_(ip.c_str()),
      port_(port),
      role_(role),
      id_(id),
      is_connected_(false) {
  if (IsInvalidIp(ip.data())) {
    throw(std::runtime_error(fmt::format("{} is invalid IP address", ip)));
  }
};

void CommunicationContext::InitializeMyRandomnessGenerator() {
  std::vector<u8> key(ABYN::RandomVector(AES_KEY_SIZE)),
      iv(ABYN::RandomVector(AES_IV_SIZE));
  my_randomness_generator_ =
      std::make_unique<ABYN::Crypto::AESRandomnessGenerator>(id_);
  my_randomness_generator_->Initialize(key.data(), iv.data());
}

void CommunicationContext::InitializeTheirRandomnessGenerator(
    std::vector<u8> &key, std::vector<u8> &iv) {
  their_randomness_generator_ =
      std::make_unique<ABYN::Crypto::AESRandomnessGenerator>(id_);
  their_randomness_generator_->Initialize(key.data(), iv.data());
}

std::string CommunicationContext::Connect() {
  if (is_connected_) {
    return std::move(fmt::format("Already connected to {}:{}\n", ip_, port_));
  } else if (role_ == ABYN::Role::Client) {
    InitializeSocketClient();
  } else {
    InitializeSocketServer();
  };

  is_connected_ = true;

  return std::move(
      fmt::format("Successfully connected to {}:{}\n", ip_, port_));
};

void CommunicationContext::ParseMessage(std::vector<u8> &&raw_message) {
  using namespace ABYN::Communication;
  auto message = GetMessage(raw_message.data());
  flatbuffers::Verifier verifier(raw_message.data(), raw_message.size());
  if (VerifyMessageBuffer(verifier) != true) {
    throw(std::runtime_error(fmt::format(
        "Parsed a corrupt message from id#{} {}:{}", id_, ip_, port_)));
  }

  auto message_type = message->message_type();

  switch (message_type) {
    case MessageType_HelloMessage: {
      auto seed_vector =
          GetHelloMessage(message->payload()->data())->input_sharing_seed();
      if (seed_vector != nullptr && seed_vector->size() > 0) {
        const u8 *seed = seed_vector->data();
        std::vector<u8> key(seed, seed + AES_KEY_SIZE),
            iv(seed + AES_KEY_SIZE, seed + AES_KEY_SIZE + AES_IV_SIZE);
        InitializeTheirRandomnessGenerator(key, iv);
        logger_->LogTrace(fmt::format(
            "Initialized the randomness generator from Party#{} with Seed: {}",
            id_, Helpers::Print::Hex(their_randomness_generator_->GetSeed())));
        logger_->LogInfo(fmt::format(
            "Received a randomness seed in hello message from Party#{}", id_));
      }
      data_storage_.SetReceivedHelloMessage(std::move(raw_message));
    } break;
    case MessageType_OutputMessage: {
      data_storage_.SetReceivedOutputMessage(std::move(raw_message));
    } break;
    default:
      throw(std::runtime_error("Didn't recognize the message type"));
  }
}

bool CommunicationContext::IsInvalidIp(const char *ip) {
  struct sockaddr_in sa;
  auto result = inet_pton(AF_INET, ip, &sa.sin_addr);
  if (result == -1) {
    throw(
        std::runtime_error(std::string("Address family not supported: ") + ip));
  }

  return result == 0;
}

void CommunicationContext::InitializeSocketServer() {
  boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port_);
  boost::asio::ip::tcp::acceptor acceptor(
      *io_service_.get(), endpoint,
      boost::asio::ip::tcp::acceptor::reuse_address(true));
  boost::system::error_code error;
  acceptor.accept(*boost_party_socket_.get(), error);
  io_service_->run();
  party_socket_ = boost_party_socket_->native_handle();
  if (error) {
    throw(std::runtime_error(error.message()));
  }
  is_connected_ = true;
};

void CommunicationContext::InitializeSocketClient() {
  boost::asio::ip::tcp::resolver resolver(*io_service_.get());
  boost::asio::ip::tcp::resolver::query query(ip_, std::to_string(port_));
  boost::system::error_code error;
  do {
    if (error) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } else {
      is_connected_ = true;
    }
    boost::asio::connect(*boost_party_socket_.get(), resolver.resolve(query),
                         error);

  } while (error);
  party_socket_ = boost_party_socket_->native_handle();
};
}