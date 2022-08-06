// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include "oblivious_transfer/ot_flavors.h"
#include "primitives/pseudo_random_generator.h"
#include "utility/fiber_waitable.h"

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
struct Kk13OtExtensionData;
struct Kk13OtExtensionReceiverData;
struct Kk13OtExtensionSenderData;
class Logger;
class BaseProvider;

class RKk13OtSender;
class RKk13OtReceiver;
class GKk13Ot128Sender;
class GKk13Ot128Receiver;
class GKk13OtBitSender;
class GKk13OtBitReceiver;
class GKk13OtSender;
class GKk13OtReceiver;

class Kk13OtVector : public FiberOnlineWaitable {
 public:
  Kk13OtVector() = delete;

  [[nodiscard]] std::size_t GetOtId() const noexcept { return ot_id_; }
  [[nodiscard]] std::size_t GetNumOts() const noexcept { return number_of_ots_; }
  [[nodiscard]] std::size_t GetBitlen() const noexcept { return bitlen_; }
  [[nodiscard]] std::size_t GetNumMessages() const noexcept { return number_of_messages_; }
  [[nodiscard]] OtProtocol GetProtocol() const noexcept { return p_; }

 protected:
  Kk13OtVector(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
               std::size_t number_of_messages, OtProtocol p);

  const std::size_t ot_id_, number_of_ots_, bitlen_, number_of_messages_;
  const OtProtocol p_;
};

class Kk13OtProviderSender : public FiberSetupWaitable {
 public:
  Kk13OtProviderSender(Kk13OtExtensionData& data) : data_(data) {}

  ~Kk13OtProviderSender() = default;

  Kk13OtProviderSender(const Kk13OtProviderSender&) = delete;

  std::unique_ptr<RKk13OtSender> RegisterROt(std::size_t number_of_ots, std::size_t bitlength,
                                             std::size_t number_of_messages);
  std::unique_ptr<GKk13OtSender> RegisterGOt(std::size_t number_of_ots, std::size_t bitlength,
                                             std::size_t number_of_messages);
  std::unique_ptr<GKk13Ot128Sender> RegisterGOt128(std::size_t number_of_ots,
                                                   std::size_t number_of_messages);
  std::unique_ptr<GKk13OtBitSender> RegisterGOtBit(std::size_t number_of_ots,
                                                   std::size_t number_of_messages);

  std::size_t GetTotalNumOts() const { return total_ots_count_; }

  std::vector<std::size_t> GetNumOts() const { return number_of_ots_; }

  std::vector<std::size_t> GetNumMessages() const { return number_of_messages_; }

  void Clear();

  void Reset();

 private:
  std::size_t total_ots_count_{0};

  std::vector<std::size_t> number_of_ots_;

  std::vector<std::size_t> number_of_messages_;

  Kk13OtExtensionData& data_;
};

class Kk13OtProviderReceiver : public FiberSetupWaitable {
 public:
  Kk13OtProviderReceiver(Kk13OtExtensionData& data) : data_(data) {}

  ~Kk13OtProviderReceiver() = default;

  Kk13OtProviderReceiver(const Kk13OtProviderReceiver&) = delete;

  std::unique_ptr<RKk13OtReceiver> RegisterROt(std::size_t number_of_ots, std::size_t bitlength,
                                               std::size_t number_of_messages);
  std::unique_ptr<GKk13OtReceiver> RegisterGOt(std::size_t number_of_ots, std::size_t bitlength,
                                               std::size_t number_of_messages);
  std::unique_ptr<GKk13Ot128Receiver> RegisterGOt128(std::size_t number_of_ots,
                                                     std::size_t number_of_messages);
  std::unique_ptr<GKk13OtBitReceiver> RegisterGOtBit(std::size_t number_of_ots,
                                                     std::size_t number_of_messages);

  std::size_t GetTotalNumOts() const { return total_ots_count_; }

  std::vector<std::size_t> GetNumOts() const { return number_of_ots_; }

  std::vector<std::size_t> GetNumMessages() const { return number_of_messages_; }

  void Clear();

  void Reset();

 private:
  std::atomic<std::size_t> total_ots_count_{0};

  std::vector<std::size_t> number_of_ots_;

  std::vector<std::size_t> number_of_messages_;

  Kk13OtExtensionData& data_;
};

// Kk13OtProvider encapsulates both sender and receiver interfaces for simplicity
class Kk13OtProvider : public FiberSetupWaitable {
 public:
  virtual ~Kk13OtProvider() = default;

  Kk13OtProvider(const Kk13OtProvider&) = delete;

  [[nodiscard]] std::unique_ptr<RKk13OtSender> RegisterSendROt(std::size_t number_of_ots = 1,
                                                               std::size_t bitlength = 1,
                                                               std::size_t number_of_messages = 2);

  [[nodiscard]] std::unique_ptr<GKk13OtSender> RegisterSendGOt(std::size_t number_of_ots = 1,
                                                               std::size_t bitlength = 1,
                                                               std::size_t number_of_messages = 2);

  [[nodiscard]] std::unique_ptr<GKk13Ot128Sender> RegisterSendGOt128(
      std::size_t number_of_ots = 1, std::size_t number_of_messages = 2);

  [[nodiscard]] std::unique_ptr<GKk13OtBitSender> RegisterSendGOtBit(
      std::size_t number_of_ots = 1, std::size_t number_of_messages = 2);

  [[nodiscard]] std::unique_ptr<RKk13OtReceiver> RegisterReceiveROt(
      std::size_t number_of_ots = 1, std::size_t bitlength = 1, std::size_t number_of_messages = 2);

  [[nodiscard]] std::unique_ptr<GKk13OtReceiver> RegisterReceiveGOt(
      std::size_t number_of_ots = 1, std::size_t bitlength = 1, std::size_t number_of_messages = 2);

  [[nodiscard]] std::unique_ptr<GKk13Ot128Receiver> RegisterReceiveGOt128(
      std::size_t number_of_ots = 1, std::size_t number_of_messages = 2);

  [[nodiscard]] std::unique_ptr<GKk13OtBitReceiver> RegisterReceiveGOtBit(
      std::size_t number_of_ots = 1, std::size_t number_of_messages = 2);

  [[nodiscard]] std::size_t GetTotalNumOtsReceiver() const {
    return receiver_provider_.GetTotalNumOts();
  }

  [[nodiscard]] std::size_t GetTotalNumOtsSender() const {
    return sender_provider_.GetTotalNumOts();
  }

  [[nodiscard]] std::vector<std::size_t> GetNumMessagesReceiver() const {
    return receiver_provider_.GetNumMessages();
  }

  [[nodiscard]] std::vector<std::size_t> GetNumMessagesSender() const {
    return sender_provider_.GetNumMessages();
  }

  virtual std::size_t GetPartyId() const = 0;

  virtual void SendSetup() = 0;

  virtual void ReceiveSetup() = 0;

  void Clear() {
    receiver_provider_.Clear();
    sender_provider_.Clear();
  }

  void Reset() {
    receiver_provider_.Reset();
    sender_provider_.Reset();
  }

  bool HasWork() { return (GetTotalNumOtsReceiver() > 0 || GetTotalNumOtsSender() > 0); }

  virtual void PreSetup() = 0;

 protected:
  Kk13OtProvider(Kk13OtExtensionData& data, BaseProvider& motion_base_provider);

  Kk13OtExtensionData& data_;

  Kk13OtProviderReceiver receiver_provider_;
  Kk13OtProviderSender sender_provider_;

  BaseProvider& motion_base_provider_;
};

/// \brief Mask the input using PRG to a vector of number_of_rows x number_of_columns
/// \param prg
/// \param input
/// \param number_of_rows
/// \param number_of_columns
std::vector<AlignedBitVector> MaskFunction(primitives::Prg& prg, std::vector<std::size_t> input,
                                           std::size_t max_element, std::size_t number_of_rows,
                                           std::size_t number_of_columns);

class Kk13OtProviderFromKk13OtExtension final : public Kk13OtProvider {
 public:
  void SendSetup() final;

  void ReceiveSetup() final;

  void PreSetup() final;

  std::size_t GetPartyId() const override;

  Kk13OtProviderFromKk13OtExtension(Kk13OtExtensionData& data, BaseOtProvider& base_ot_provider,
                                    BaseProvider&);

 private:
  BaseOtProvider& base_ot_provider_;
};

class Kk13OtProviderManager {
 public:
  Kk13OtProviderManager(communication::CommunicationLayer&, BaseOtProvider&, BaseProvider&);
  ~Kk13OtProviderManager();

  std::vector<std::unique_ptr<Kk13OtProvider>>& GetProviders() { return providers_; }
  Kk13OtProvider& GetProvider(std::size_t party_id) { return *providers_[party_id]; }

  bool HasWork();

  void PreSetup() {
    for (auto& provider : providers_) {
      if (provider) provider->PreSetup();
    }
  }

 private:
  communication::CommunicationLayer& communication_layer_;
  std::size_t number_of_parties_;
  std::vector<std::unique_ptr<Kk13OtProvider>> providers_;
  std::vector<std::unique_ptr<Kk13OtExtensionData>> data_;
};

}  // namespace encrypto::motion