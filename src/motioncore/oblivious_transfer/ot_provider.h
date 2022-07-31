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
#include "utility/fiber_waitable.h"

namespace encrypto::motion::communication {

class CommunicationLayer;
class MessageManager;

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
  kGOtBit = 7,
  kInvalidOt = 8,
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
class BasicOtSender;
class BasicOtReceiver;
class GOt128Sender;
class GOt128Receiver;
class GOtBitSender;
class GOtBitReceiver;
class GOtSender;
class GOtReceiver;

class OtVector {
 public:
  OtVector() = delete;
  virtual ~OtVector() = default;

  [[nodiscard]] std::size_t GetOtId() const noexcept { return ot_id_; }
  [[nodiscard]] std::size_t GetNumOts() const noexcept { return number_of_ots_; }
  [[nodiscard]] std::size_t GetBitlength() const noexcept { return bitlength_; }
  [[nodiscard]] virtual OtProtocol GetProtocol() const noexcept = 0;

 protected:
  OtVector(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
           OtExtensionData& data);

  const std::size_t ot_id_;
  const std::size_t number_of_ots_;
  const std::size_t bitlength_;

  // reference to data storage and context
  OtExtensionData& data_;
};

class OtProviderSender : public FiberSetupWaitable {
 public:
  OtProviderSender(OtExtensionData& data, std::size_t party_id)
      : data_(data), party_id_(party_id) {}

  ~OtProviderSender() = default;

  OtProviderSender(const OtProviderSender&) = delete;

  std::unique_ptr<ROtSender> RegisterROt(std::size_t number_of_ots, std::size_t bitlength);
  std::unique_ptr<XcOtSender> RegisterXcOt(std::size_t number_of_ots, std::size_t bitlength);
  std::unique_ptr<FixedXcOt128Sender> RegisterFixedXcOt128s(std::size_t number_of_ots);
  std::unique_ptr<XcOtBitSender> RegisterXcOtBits(std::size_t number_of_ots);
  template <typename T>
  std::unique_ptr<AcOtSender<T>> RegisterAcOt(std::size_t number_of_ots, std::size_t vector_size);
  std::unique_ptr<GOtSender> RegisterGOt(std::size_t number_of_ots, std::size_t bitlength);
  std::unique_ptr<GOt128Sender> RegisterGOt128(std::size_t number_of_ots);
  std::unique_ptr<GOtBitSender> RegisterGOtBit(std::size_t number_of_ots);

  auto GetNumOts() const { return total_ots_count_; }

  void Clear();

  void Reset();

 private:
  std::size_t total_ots_count_{0};

  OtExtensionData& data_;

  std::size_t party_id_;
};

class OtProviderReceiver : public FiberSetupWaitable {
 public:
  OtProviderReceiver(OtExtensionData& data, std::size_t party_id)
      : data_(data), party_id_(party_id) {}

  ~OtProviderReceiver() = default;

  OtProviderReceiver(const OtProviderReceiver&) = delete;

  std::unique_ptr<ROtReceiver> RegisterROt(std::size_t number_of_ots, std::size_t bitlength);
  std::unique_ptr<XcOtReceiver> RegisterXcOt(std::size_t number_of_ots, std::size_t bitlength);
  std::unique_ptr<FixedXcOt128Receiver> RegisterFixedXcOt128s(std::size_t number_of_ots);
  std::unique_ptr<XcOtBitReceiver> RegisterXcOtBits(std::size_t number_of_ots);
  template <typename T>
  std::unique_ptr<AcOtReceiver<T>> RegisterAcOt(std::size_t number_of_ots, std::size_t vector_size);
  std::unique_ptr<GOtReceiver> RegisterGOt(std::size_t number_of_ots, std::size_t bitlength);
  std::unique_ptr<GOt128Receiver> RegisterGOt128(std::size_t number_of_ots);
  std::unique_ptr<GOtBitReceiver> RegisterGOtBit(std::size_t number_of_ots);

  std::size_t GetNumOts() const { return total_ots_count_; }

  void Clear();
  void Reset();

 private:
  std::atomic<std::size_t> total_ots_count_{0};

  OtExtensionData& data_;

  std::size_t party_id_;
};

// OtProvider encapsulates both sender and receiver interfaces for simplicity
class OtProvider : public FiberSetupWaitable {
 public:
  virtual ~OtProvider() = default;

  OtProvider(const OtProvider&) = delete;

  [[nodiscard]] virtual std::unique_ptr<ROtSender> RegisterSendROt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bitlength = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<XcOtSender> RegisterSendXcOt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bitlength = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<FixedXcOt128Sender> RegisterSendFixedXcOt128(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<XcOtBitSender> RegisterSendXcOtBit(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<BasicOtSender> RegisterSendAcOt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bit_length = 8,
      [[maybe_unused]] std::size_t vector_size = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<GOtSender> RegisterSendGOt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bitlength = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<GOt128Sender> RegisterSendGOt128(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<GOtBitSender> RegisterSendGOtBit(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<ROtReceiver> RegisterReceiveROt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bitlength = 1) {
    throw std::runtime_error("not implemented");
  }
  [[nodiscard]] virtual std::unique_ptr<XcOtReceiver> RegisterReceiveXcOt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bitlength = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<FixedXcOt128Receiver> RegisterReceiveFixedXcOt128(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<XcOtBitReceiver> RegisterReceiveXcOtBit(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<BasicOtReceiver> RegisterReceiveAcOt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bitlength = 8,
      [[maybe_unused]] std::size_t vector_size = 1) {
    throw std::runtime_error("not implemented");
  }
  [[nodiscard]] virtual std::unique_ptr<GOtReceiver> RegisterReceiveGOt(
      [[maybe_unused]] std::size_t number_of_ots = 1, [[maybe_unused]] std::size_t bitlength = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<GOt128Receiver> RegisterReceiveGOt128(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::unique_ptr<GOtBitReceiver> RegisterReceiveGOtBit(
      [[maybe_unused]] std::size_t number_of_ots = 1) {
    throw std::runtime_error("not implemented");
  }

  [[nodiscard]] virtual std::size_t GetNumOtsReceiver() const = 0;

  [[nodiscard]] virtual std::size_t GetNumOtsSender() const = 0;

  [[nodiscard]] bool HasWork() const { return (GetNumOtsReceiver() > 0 || GetNumOtsSender() > 0); }

  [[nodiscard]] virtual std::size_t GetPartyId() = 0;

  virtual void SendSetup() = 0;
  virtual void ReceiveSetup() = 0;

  virtual void PreSetup() = 0;

  virtual void Clear() { throw std::runtime_error("not implemented"); }

  virtual void Reset() { throw std::runtime_error("not implemented"); }

 protected:
  OtProvider() = default;
};

class OtProviderFromFile : public OtProvider {
  // TODO
};

class OtProviderFromBaseOTs : public OtProvider {
  // TODO
};

class OtProviderFromOtExtension final : public OtProvider {
 public:
  [[nodiscard]] std::unique_ptr<ROtSender> RegisterSendROt(std::size_t number_of_ots,
                                                           std::size_t bitlength) override;

  [[nodiscard]] std::unique_ptr<XcOtSender> RegisterSendXcOt(std::size_t number_of_ots,
                                                             std::size_t bitlength) override;

  [[nodiscard]] std::unique_ptr<FixedXcOt128Sender> RegisterSendFixedXcOt128(
      std::size_t number_of_ots) override;

  [[nodiscard]] std::unique_ptr<XcOtBitSender> RegisterSendXcOtBit(
      std::size_t number_of_ots) override;

  [[nodiscard]] std::unique_ptr<BasicOtSender> RegisterSendAcOt(std::size_t number_of_ots,
                                                                std::size_t bitlength,
                                                                std::size_t vector_size) override;

  [[nodiscard]] std::unique_ptr<GOtSender> RegisterSendGOt(std::size_t number_of_ots,
                                                           std::size_t bitlength) override;

  [[nodiscard]] std::unique_ptr<GOt128Sender> RegisterSendGOt128(
      std::size_t number_of_ots) override;

  [[nodiscard]] std::unique_ptr<GOtBitSender> RegisterSendGOtBit(
      std::size_t number_of_ots) override;

  [[nodiscard]] std::unique_ptr<ROtReceiver> RegisterReceiveROt(std::size_t number_of_ots,
                                                                std::size_t bitlength) override;

  [[nodiscard]] std::unique_ptr<XcOtReceiver> RegisterReceiveXcOt(std::size_t number_of_ots,
                                                                  std::size_t bitlength) override;

  [[nodiscard]] std::unique_ptr<FixedXcOt128Receiver> RegisterReceiveFixedXcOt128(
      std::size_t number_of_ots) override;

  [[nodiscard]] std::unique_ptr<XcOtBitReceiver> RegisterReceiveXcOtBit(
      std::size_t number_of_ots) override;

  [[nodiscard]] std::unique_ptr<BasicOtReceiver> RegisterReceiveAcOt(
      std::size_t number_of_ots, std::size_t bitlength, std::size_t vector_size) override;

  [[nodiscard]] std::unique_ptr<GOtReceiver> RegisterReceiveGOt(std::size_t number_of_ots,
                                                                std::size_t bitlength) override;

  [[nodiscard]] std::unique_ptr<GOt128Receiver> RegisterReceiveGOt128(
      std::size_t number_of_ots) override;

  [[nodiscard]] std::unique_ptr<GOtBitReceiver> RegisterReceiveGOtBit(
      std::size_t number_of_ots) override;

  void SendSetup() final;

  void ReceiveSetup() final;

  void PreSetup() final;

  OtProviderFromOtExtension(OtExtensionData& data, BaseOtProvider& base_ot_provider, BaseProvider&,
                            std::size_t party_id);

  std::size_t GetPartyId() final;

  void SetBaseOtOffset(std::size_t offset);

  std::size_t GetBaseOtOffset() const;

  [[nodiscard]] std::size_t GetNumOtsReceiver() const final {
    return receiver_provider_.GetNumOts();
  }

  [[nodiscard]] std::size_t GetNumOtsSender() const final { return sender_provider_.GetNumOts(); }

 private:
  OtExtensionData& data_;
  BaseOtProvider& base_ot_provider_;
  BaseProvider& motion_base_provider_;
  OtProviderReceiver receiver_provider_;
  OtProviderSender sender_provider_;
};

class OtProviderFromThirdParty : public OtProvider {
  // TODO
};

class OtProviderFromMultipleThirdParties : public OtProvider {
  // TODO
};

class OtProviderManager {
 public:
  OtProviderManager(communication::CommunicationLayer&, BaseOtProvider&, BaseProvider&);
  ~OtProviderManager();

  void PreSetup() {
    for (auto& provider : providers_) {
      if (provider) provider->PreSetup();
    }
  }

  std::vector<std::unique_ptr<OtProvider>>& GetProviders() { return providers_; }
  OtProvider& GetProvider(std::size_t party_id) { return *providers_.at(party_id); }

  bool HasWork();

 private:
  communication::CommunicationLayer& communication_layer_;
  std::vector<std::unique_ptr<OtProvider>> providers_;
  std::vector<std::unique_ptr<OtExtensionData>> data_;
};

}  // namespace encrypto::motion
