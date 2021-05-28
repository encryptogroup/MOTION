// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#pragma once

#include <array>
#include <atomic>
#include <memory>
#include <unordered_map>

#include <flatbuffers/flatbuffers.h>

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion {

class BaseOtProvider;
struct BaseOtData;
struct OtExtensionData;
struct OtExtensionReceiverData;
struct OtExtensionSenderData;
class Logger;
class BaseProvider;

enum OtProtocol : unsigned int {
  kGOt = 0,   // general OT
  kROt = 1,   // random OT
  kXcOt = 2,  // XOR-correlated OT
  kAcOt = 3,  // additively-correlated OT
  kFixedXcOt128 = 4,
  kXcOtBit = 5,
  kGOt128 = 6,
  kInvalidOt = 7,
};

class ROtSender;
class ROtReceiver;
class XcOtSender;
class XcOtReceiver;
class FixedXcOt128Sender;
class FixedXcOt128Receiver;
class XcOtBitSender;
class XcOtBitReceiver;
template <typename T>
class AcOtSender;
template <typename T>
class AcOtReceiver;
class GOt128Sender;
class GOt128Receiver;
class GOtBitSender;
class GOtBitReceiver;
class GOtSender;
class GOtReceiver;

class OtVector {
 public:
  OtVector() = delete;

  [[nodiscard]] std::size_t GetOtId() const noexcept { return ot_id_; }
  [[nodiscard]] std::size_t GetNumOts() const noexcept { return number_of_ots_; }
  [[nodiscard]] std::size_t GetBitlen() const noexcept { return bitlen_; }
  [[nodiscard]] OtProtocol GetProtocol() const noexcept { return p_; }

 protected:
  OtVector(const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
           const OtProtocol p,
           const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);

  const std::size_t ot_id_, number_of_ots_, bitlen_;
  const OtProtocol p_;

  std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function_;
};

class OtProviderSender {
 public:
  OtProviderSender(OtExtensionSenderData& data, std::size_t party_id,
                   std::shared_ptr<Logger> logger)
      : data_(data), party_id_(party_id), logger_(std::move(logger)) {}

  ~OtProviderSender() = default;

  OtProviderSender(const OtProviderSender&) = delete;

  std::unique_ptr<ROtSender> RegisterROt(
      std::size_t number_of_ots, std::size_t bitlength,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<XcOtSender> RegisterXcOt(
      std::size_t number_of_ots, std::size_t bitlength,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<FixedXcOt128Sender> RegisterFixedXcOt128s(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<XcOtBitSender> RegisterXcOtBits(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  template <typename T>
  std::unique_ptr<AcOtSender<T>> RegisterAcOt(
      std::size_t number_of_ots, std::size_t vector_size,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<GOtSender> RegisterGOt(
      std::size_t number_of_ots, std::size_t bitlength,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<GOt128Sender> RegisterGOt128(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<GOtBitSender> RegisterGOtBit(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);

  auto GetNumOts() const { return total_ots_count_; }

  void Clear();

  void Reset();

 private:
  std::size_t total_ots_count_{0};

  OtExtensionSenderData& data_;

  std::size_t party_id_;

  std::shared_ptr<Logger> logger_;
};

class OtProviderReceiver {
 public:
  OtProviderReceiver(OtExtensionReceiverData& data, std::size_t party_id,
                     std::shared_ptr<Logger> logger)
      : data_(data), party_id_(party_id), logger_(std::move(logger)) {}

  ~OtProviderReceiver() = default;

  OtProviderReceiver(const OtProviderReceiver&) = delete;

  std::unique_ptr<ROtReceiver> RegisterROt(
      std::size_t number_of_ots, std::size_t bitlength,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<XcOtReceiver> RegisterXcOt(
      std::size_t number_of_ots, std::size_t bitlength,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<FixedXcOt128Receiver> RegisterFixedXcOt128s(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<XcOtBitReceiver> RegisterXcOtBits(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  template <typename T>
  std::unique_ptr<AcOtReceiver<T>> RegisterAcOt(
      std::size_t number_of_ots, std::size_t vector_size,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<GOtReceiver> RegisterGOt(
      std::size_t number_of_ots, std::size_t bitlength,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<GOt128Receiver> RegisterGOt128(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
  std::unique_ptr<GOtBitReceiver> RegisterGOtBit(
      const std::size_t number_of_ots,
      const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);

  std::size_t GetNumOts() const { return total_ots_count_; }

  void Clear();
  void Reset();

 private:
  std::atomic<std::size_t> total_ots_count_{0};

  OtExtensionReceiverData& data_;

  std::size_t party_id_;

  std::shared_ptr<Logger> logger_;
};

// OtProvider encapsulates both sender and receiver interfaces for simplicity
class OtProvider {
 public:
  virtual ~OtProvider() = default;

  OtProvider(const OtProvider&) = delete;

  [[nodiscard]] std::unique_ptr<ROtSender> RegisterSendROt(std::size_t number_of_ots = 1,
                                                           std::size_t bitlength = 1);

  [[nodiscard]] std::unique_ptr<XcOtSender> RegisterSendXcOt(std::size_t number_of_ots = 1,
                                                             std::size_t bitlength = 1);

  [[nodiscard]] std::unique_ptr<FixedXcOt128Sender> RegisterSendFixedXcOt128(
      std::size_t number_of_ots = 1);

  [[nodiscard]] std::unique_ptr<XcOtBitSender> RegisterSendXcOtBit(std::size_t number_of_ots = 1);

  template <typename T>
  [[nodiscard]] std::unique_ptr<AcOtSender<T>> RegisterSendAcOt(std::size_t number_of_ots = 1,
                                                                std::size_t vector_size = 1);

  [[nodiscard]] std::unique_ptr<GOtSender> RegisterSendGOt(std::size_t number_of_ots = 1,
                                                           std::size_t bitlength = 1);

  [[nodiscard]] std::unique_ptr<GOt128Sender> RegisterSendGOt128(std::size_t number_of_ots = 1);

  [[nodiscard]] std::unique_ptr<GOtBitSender> RegisterSendGOtBit(std::size_t number_of_ots = 1);

  [[nodiscard]] std::unique_ptr<ROtReceiver> RegisterReceiveROt(std::size_t number_of_ots = 1,
                                                                std::size_t bitlength = 1);

  [[nodiscard]] std::unique_ptr<XcOtReceiver> RegisterReceiveXcOt(std::size_t number_of_ots = 1,
                                                                  std::size_t bitlength = 1);

  [[nodiscard]] std::unique_ptr<FixedXcOt128Receiver> RegisterReceiveFixedXcOt128(
      std::size_t number_of_ots = 1);

  [[nodiscard]] std::unique_ptr<XcOtBitReceiver> RegisterReceiveXcOtBit(
      std::size_t number_of_ots = 1);

  template <typename T>
  [[nodiscard]] std::unique_ptr<AcOtReceiver<T>> RegisterReceiveAcOt(std::size_t number_of_ots = 1,
                                                                     std::size_t vector_size = 1);
  [[nodiscard]] std::unique_ptr<GOtReceiver> RegisterReceiveGOt(std::size_t number_of_ots = 1,
                                                                std::size_t bitlength = 1);

  [[nodiscard]] std::unique_ptr<GOt128Receiver> RegisterReceiveGOt128(
      std::size_t number_of_ots = 1);

  [[nodiscard]] std::unique_ptr<GOtBitReceiver> RegisterReceiveGOtBit(
      std::size_t number_of_ots = 1);

  [[nodiscard]] std::size_t GetNumOtsReceiver() const { return receiver_provider_.GetNumOts(); }

  [[nodiscard]] std::size_t GetNumOtsSender() const { return sender_provider_.GetNumOts(); }

  virtual void SendSetup() = 0;
  virtual void ReceiveSetup() = 0;

  void WaitSetup() const;

  void Clear() {
    receiver_provider_.Clear();
    sender_provider_.Clear();
  }

  void Reset() {
    receiver_provider_.Reset();
    sender_provider_.Reset();
  }

 protected:
  OtProvider(std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function,
             OtExtensionData& data, std::size_t party_id, std::shared_ptr<Logger> logger);

  std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function_;
  OtExtensionData& data_;
  OtProviderReceiver receiver_provider_;
  OtProviderSender sender_provider_;
};

class OtProviderFromFile : public OtProvider {
  // TODO
};

class OtProviderFromBaseOTs : public OtProvider {
  // TODO
};

class OtProviderFromOtExtension final : public OtProvider {
 public:
  void SendSetup() final;

  void ReceiveSetup() final;

  OtProviderFromOtExtension(std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function,
                            OtExtensionData& data, const BaseOtData& base_ot_data, BaseProvider&,
                            std::size_t party_id, std::shared_ptr<Logger> logger);

 private:
  const BaseOtData& base_ot_data_;
  BaseProvider& motion_base_provider_;
};

class OtProviderFromThirdParty : public OtProvider {
  // TODO
};

class OtProviderFromMultipleThirdParties : public OtProvider {
  // TODO
};

class OtProviderManager {
 public:
  OtProviderManager(communication::CommunicationLayer&, const BaseOtProvider&, BaseProvider&,
                    std::shared_ptr<Logger> logger);
  ~OtProviderManager();

  std::vector<std::unique_ptr<OtProvider>>& GetProviders() { return providers_; }
  OtProvider& GetProvider(std::size_t party_id) { return *providers_.at(party_id); }

 private:
  communication::CommunicationLayer& communication_layer_;
  std::size_t number_of_parties_;
  std::vector<std::unique_ptr<OtProvider>> providers_;
  std::vector<std::unique_ptr<OtExtensionData>> data_;
};

}  // namespace encrypto::motion
