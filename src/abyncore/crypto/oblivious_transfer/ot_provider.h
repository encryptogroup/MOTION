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
#include <memory>
#include <unordered_map>

#include "flatbuffers/flatbuffers.h"

#include "communication/ot_extension_message.h"
#include "crypto/pseudo_random_generator.h"
#include "utility/bit_vector.h"
#include "utility/condition.h"
#include "utility/data_storage.h"

namespace ENCRYPTO {

namespace ObliviousTransfer {

enum OTProtocol : uint {
  GOT = 0,   // general OT
  ROT = 1,   // random OT
  XCOT = 2,  // XOR-correlated OT
  ACOT = 3,  // additively-correlated OT
  invalid_OT = 4
};

class OTVector {
 public:
  OTVector() = delete;

 protected:
  OTVector(const std::size_t id, const std::size_t num_ots, const std::size_t N,
           const std::size_t bitlen, const OTProtocol p,
           const std::shared_ptr<ABYN::DataStorage> &data_storage,
           const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : id_(id),
        num_ots_(num_ots),
        N_(N),
        bitlen_(bitlen),
        p_(p),
        data_storage_(data_storage),
        Send_(Send) {}

  const std::size_t id_, num_ots_, N_, bitlen_;
  const OTProtocol p_;

  std::shared_ptr<ABYN::DataStorage> data_storage_;
  std::function<void(flatbuffers::FlatBufferBuilder &&)> Send_;
};

class OTVectorSender : public OTVector {
 public:
  const std::vector<BitVector<>> &GetInputs() { return inputs_; };
  virtual const std::vector<BitVector<>> &GetOutputs() {
    WaitSetup();
    auto &ote = data_storage_->GetOTExtensionSenderData();
    if (outputs_.empty()) {
      for (auto i = 0ull; i < num_ots_; ++i) {
        auto bv = ote->y0_.at(id_ + i);
        bv.Append(ote->y1_.at(id_ + i));
        outputs_.push_back(std::move(bv));
      }
    }
    return outputs_;
  };

  virtual void SetInputs(const std::vector<BitVector<>> &v) = 0;
  virtual void SetInputs(std::vector<BitVector<>> &&v) = 0;

  virtual void SendMessages() = 0;

  void WaitSetup() {
    auto &cond = data_storage_->GetOTExtensionSenderData()->setup_finished_condition_;
    while (!(*cond)()) {
      cond->WaitFor(std::chrono::milliseconds(1));
    }
  };

 protected:
  OTVectorSender(const std::size_t id, const std::size_t num_ots, const std::size_t N,
                 const std::size_t bitlen, const OTProtocol p,
                 const std::shared_ptr<ABYN::DataStorage> &data_storage,
                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : OTVector(id, num_ots, N, bitlen, p, data_storage, Send) {
    Reserve(id, num_ots, bitlen);
  }

  void Reserve(const std::size_t id, const std::size_t num_ots, const std::size_t bitlen) {
    auto &data = data_storage_->GetOTExtensionSenderData();
    data->y0_.resize(id + num_ots);
    data->y1_.resize(id + num_ots);
    data->bitlengths_.resize(id + num_ots);
    data->corrections_.Resize(id + num_ots);
    for (auto i = 0ull; i < num_ots; ++i) {
      data->bitlengths_.at(id + i) = bitlen;
    }
    data->num_ots_in_batch_.emplace(id, num_ots);
  }

  std::vector<BitVector<>> inputs_, outputs_;
};

class GOTVectorSender final : public OTVectorSender {
 public:
  GOTVectorSender(const std::size_t id, const std::size_t num_ots, const std::size_t N,
                  const std::size_t bitlen, const std::shared_ptr<ABYN::DataStorage> &data_storage,
                  const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : OTVectorSender(id, num_ots, N, bitlen, OTProtocol::GOT, data_storage, Send) {
    auto &ote_data = data_storage_->GetOTExtensionSenderData();
    ote_data->received_correction_offsets_cond_.emplace(
        id_, std::make_unique<Condition>([this, &ote_data]() {
          return ote_data->received_correction_offsets_.find(id_) !=
                 ote_data->received_correction_offsets_.end();
        }));
  }

  void SetInputs(std::vector<BitVector<>> &&v) final {
    for ([[maybe_unused]] auto &bv : v) {
      assert(bv.GetSize() == (bitlen_ * 2));
    }
    inputs_ = std::move(v);
    outputs_ = inputs_;
  }

  void SetInputs(const std::vector<BitVector<>> &v) final {
    for ([[maybe_unused]] auto &bv : v) {
      assert(bv.GetSize() == (bitlen_ * 2));
    }
    inputs_ = v;
    outputs_ = inputs_;
  }

  // blocking wait for correction bits
  void SendMessages() final {
    assert(!inputs_.empty());
    WaitSetup();
    auto &ote = data_storage_->GetOTExtensionSenderData();
    ABYN::Helpers::WaitFor(*ote->received_correction_offsets_cond_.at(id_));
    auto corrections = ote->corrections_.Subset(id_, id_ + num_ots_);
    assert(inputs_.size() == corrections.GetSize());

    BitVector<> buffer;
    for (auto i = 0ull; i < num_ots_; ++i) {
      const auto bv_0 = inputs_.at(i).Subset(0, bitlen_);
      const auto bv_1 = inputs_.at(i).Subset(bitlen_, bitlen_ * 2);
      if (corrections[i]) {
        buffer.Append(bv_1 ^ ote->y0_.at(id_ + i));
        buffer.Append(bv_0 ^ ote->y1_.at(id_ + i));
      } else {
        buffer.Append(bv_0 ^ ote->y0_.at(id_ + i));
        buffer.Append(bv_1 ^ ote->y1_.at(id_ + i));
      }
    }
    Send_(ABYN::Communication::BuildOTExtensionMessageSender(buffer.GetData().data(),
                                                             buffer.GetData().size(), id_));
  }
};

class COTVectorSender final : public OTVectorSender {
 public:
  COTVectorSender(const std::size_t id, const std::size_t num_ots, const std::size_t bitlen,
                  OTProtocol p, const std::shared_ptr<ABYN::DataStorage> &data_storage,
                  const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : OTVectorSender(id, num_ots, 2, bitlen, p, data_storage, Send) {
    if (p == OTProtocol::ACOT &&
        (bitlen != 8u && bitlen != 16u && bitlen != 32u && bitlen != 64u)) {
      throw std::runtime_error(fmt::format(
          "Invalid parameter bitlen={}, only 8, 16, 32, or 64 are allowed in ACOT", bitlen_));
    }
    auto &ote_data = data_storage_->GetOTExtensionSenderData();
    ote_data->received_correction_offsets_cond_.emplace(
        id_, std::make_unique<Condition>([this, &ote_data]() {
          return ote_data->received_correction_offsets_.find(id_) !=
                 ote_data->received_correction_offsets_.end();
        }));
  }

  void SetInputs(std::vector<BitVector<>> &&v) final {
    for ([[maybe_unused]] auto &bv : v) {
      assert(bv.GetSize() == (bitlen_));
    }
    inputs_ = std::move(v);
  }

  void SetInputs(const std::vector<BitVector<>> &v) final {
    for ([[maybe_unused]] auto &bv : v) {
      assert(bv.GetSize() == (bitlen_));
    }
    inputs_ = v;
  }

  const std::vector<BitVector<>> &GetOutputs() final {
    if (inputs_.empty()) {
      throw std::runtime_error("Inputs have to be chosen before calling GetOutputs()");
    }
    WaitSetup();
    auto &ote = data_storage_->GetOTExtensionSenderData();
    ABYN::Helpers::WaitFor(*ote->received_correction_offsets_cond_.at(id_));
    if (outputs_.empty()) {
      const auto corrections = ote->corrections_.Subset(id_, id_ + num_ots_);
      for (auto i = 0ull; i < num_ots_; ++i) {
        BitVector<> bv;
        if (corrections[i]) {
          bv = ote->y1_.at(id_ + i);
        } else {
          bv = ote->y0_.at(id_ + i);
        }
        if (p_ == OTProtocol::ACOT) {
          if (corrections[i]) {
            bv.Append(ote->y1_.at(id_ + i));
          } else {
            bv.Append(ote->y0_.at(id_ + i));
          }
          switch (bitlen_) {
            case (8u): {
              *reinterpret_cast<uint8_t *>(bv.GetMutableData().data() + 1) +=
                  *reinterpret_cast<const uint8_t *>(inputs_.at(i).GetData().data());
              break;
            }
            case (16u): {
              *reinterpret_cast<uint16_t *>(bv.GetMutableData().data() + 2) +=
                  *reinterpret_cast<const uint16_t *>(inputs_.at(i).GetData().data());
              break;
            }
            case (32u): {
              *reinterpret_cast<uint32_t *>(bv.GetMutableData().data() + 4) +=
                  *reinterpret_cast<const uint32_t *>(inputs_.at(i).GetData().data());
              break;
            }
            case (64u): {
              *reinterpret_cast<uint64_t *>(bv.GetMutableData().data() + 8) +=
                  *reinterpret_cast<const uint64_t *>(inputs_.at(i).GetData().data());
              break;
            }
          }
        } else {  // OTProtocol::XCOT
          bv.Append(inputs_.at(i) ^ bv);
        }
        outputs_.emplace_back(std::move(bv));
      }
    }
    return outputs_;
  }

  void SendMessages() final {
    if (inputs_.empty()) {
      throw std::runtime_error("Inputs have to be chosen before calling SendMessages()");
    }
    WaitSetup();
    auto &ote = data_storage_->GetOTExtensionSenderData();
    BitVector<> buffer;
    for (auto i = 0ull; i < num_ots_; ++i) {
      if (p_ == OTProtocol::ACOT) {
        BitVector bv = ote->y0_.at(id_ + i);
        switch (bitlen_) {
          case 8u: {
            *(reinterpret_cast<std::uint8_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint8_t *>(inputs_.at(i).GetMutableData().data()));
            *(reinterpret_cast<std::uint8_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint8_t *>(
                    ote->y1_.at(id_ + i).GetMutableData().data()));

            break;
          }
          case 16u: {
            *(reinterpret_cast<std::uint16_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint16_t *>(inputs_.at(i).GetMutableData().data()));
            *(reinterpret_cast<std::uint16_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint16_t *>(
                    ote->y1_.at(id_ + i).GetMutableData().data()));
            break;
          }
          case 32u: {
            *(reinterpret_cast<std::uint32_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint32_t *>(inputs_.at(i).GetMutableData().data()));
            *(reinterpret_cast<std::uint32_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint32_t *>(
                    ote->y1_.at(id_ + i).GetMutableData().data()));
            break;
          }
          case 64u: {
            *(reinterpret_cast<std::uint64_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint64_t *>(inputs_.at(i).GetMutableData().data()));
            *(reinterpret_cast<std::uint64_t *>(bv.GetMutableData().data())) +=
                *(reinterpret_cast<const std::uint64_t *>(
                    ote->y1_.at(id_ + i).GetMutableData().data()));
            break;
          }
          default: {
            throw std::runtime_error(fmt::format("Unsupported bitlength {}", bitlen_));
          }
        }
        buffer.Append(bv);
      } else if (p_ == OTProtocol::XCOT) {
        buffer.Append(inputs_.at(i) ^ ote->y0_.at(id_ + i) ^ ote->y1_.at(id_ + i));
      } else {
        throw std::runtime_error("Unknown OT protocol");
      }
    }
    Send_(ABYN::Communication::BuildOTExtensionMessageSender(buffer.GetData().data(),
                                                             buffer.GetData().size(), id_));
  }
};

class ROTVectorSender final : public OTVectorSender {
 public:
  ROTVectorSender(const std::size_t id, const std::size_t num_ots, const std::size_t N,
                  const std::size_t bitlen, const std::shared_ptr<ABYN::DataStorage> &data_storage,
                  const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : OTVectorSender(id, num_ots, N, bitlen, OTProtocol::ROT, data_storage, Send) {}

  void SetInputs([[maybe_unused]] std::vector<BitVector<>> &&v) final {
    throw std::runtime_error("Inputs are random in ROT and thus cannot be set");
  }

  void SetInputs([[maybe_unused]] const std::vector<BitVector<>> &v) final {
    throw std::runtime_error("Inputs are random in ROT and thus cannot be set");
  }

  void SendMessages() final {
    throw std::runtime_error("Inputs in ROT are available locally and thus do not need to be sent");
  }
};

class OTVectorReceiver : public OTVector {
 public:
  virtual void SetChoices(const BitVector<> &v) = 0;

  virtual void SetChoices(BitVector<> &&v) = 0;

  const virtual BitVector<> &GetChoices() = 0;

  const virtual std::vector<BitVector<>> &GetOutputs() = 0;

  virtual void SendCorrections() = 0;

  void WaitSetup() {
    auto &cond = data_storage_->GetOTExtensionReceiverData()->setup_finished_condition_;
    while (!(*cond)()) {
      cond->WaitFor(std::chrono::milliseconds(1));
    }
  };

 protected:
  OTVectorReceiver(const std::size_t id, const std::size_t num_ots, const std::size_t N,
                   const std::size_t bitlen, const OTProtocol p,
                   const std::shared_ptr<ABYN::DataStorage> &data_storage,
                   std::function<void(flatbuffers::FlatBufferBuilder &&)> Send)
      : OTVector(id, num_ots, N, bitlen, p, data_storage, Send) {
    Reserve(id, num_ots, bitlen);
  }

  void Reserve(const std::size_t id, const std::size_t num_ots, const std::size_t bitlen) {
    auto &data = data_storage_->GetOTExtensionReceiverData();
    data->outputs_.resize(id + num_ots);
    data->bitlengths_.resize(id + num_ots);
    for (auto i = 0ull; i < num_ots; ++i) {
      data->bitlengths_.at(id + i) = bitlen;
    }
    data->num_ots_in_batch_.emplace(id, num_ots);
  }

  BitVector<> choices_;
  std::vector<BitVector<>> messages_;
};

class GOTVectorReceiver final : public OTVectorReceiver {
 public:
  GOTVectorReceiver(const std::size_t id, const std::size_t num_ots, const std::size_t N,
                    const std::size_t bitlen,
                    const std::shared_ptr<ABYN::DataStorage> &data_storage,
                    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : OTVectorReceiver(id, num_ots, N, bitlen, OTProtocol::GOT, data_storage, Send) {
    data_storage_->GetOTExtensionReceiverData()->num_messages_.emplace(id_, 2);
  }

  void SetChoices(BitVector<> &&v) final {
    assert(v.GetSize() == num_ots_);
    choices_ = std::move(v);
    auto &ote = data_storage_->GetOTExtensionReceiverData();
    ote->real_choices_->Copy(id_, choices_);

    auto &cond = ote->real_choices_cond_.at(id_);
    {
      std::scoped_lock lock(cond->GetMutex());
      ote->set_real_choices_.emplace(id_);
    }
    cond->NotifyOne();
  }

  void SetChoices(const BitVector<> &v) final {
    assert(v.GetSize() == num_ots_);
    choices_ = v;

    auto &ote = data_storage_->GetOTExtensionReceiverData();
    ote->real_choices_->Copy(id_, choices_);

    auto &cond = ote->real_choices_cond_.at(id_);
    {
      std::scoped_lock lock(cond->GetMutex());
      ote->set_real_choices_.emplace(id_);
    }
    cond->NotifyOne();
  }

  const BitVector<> &GetChoices() final { return choices_; };

  void SendCorrections() final {
    if (choices_.Empty()) {
      throw std::runtime_error("Choices in GOT must be set before calling SendCorrections()");
    }

    const auto &ote = data_storage_->GetOTExtensionReceiverData();
    auto corrections = choices_ ^ ote->random_choices_->Subset(id_, id_ + num_ots_);
    Send_(ABYN::Communication::BuildOTExtensionMessageReceiverCorrections(
        corrections.GetData().data(), corrections.GetData().size(), id_));
    corrections_sent_ = true;
  }

  const std::vector<BitVector<>> &GetOutputs() final {
    if (!corrections_sent_) {
      throw std::runtime_error("In GOT, corrections must be set before calling GetOutputs()");
    }
    WaitSetup();
    auto &ote = data_storage_->GetOTExtensionReceiverData();
    auto &cond = ote->output_conditions_.at(id_);
    ABYN::Helpers::WaitFor(*cond);
    if (messages_.empty()) {
      for (auto i = 0ull; i < num_ots_; ++i) {
        if (ote->outputs_.at(id_ + i).GetSize() > 0) {
          messages_.emplace_back(std::move(ote->outputs_.at(id_ + i)));
        }
      }
    }
    return messages_;
  };

 private:
  bool corrections_sent_ = false;
};

class COTVectorReceiver final : public OTVectorReceiver {
 public:
  COTVectorReceiver(const std::size_t id, const std::size_t num_ots, const std::size_t bitlen,
                    OTProtocol p, const std::shared_ptr<ABYN::DataStorage> &data_storage,
                    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : OTVectorReceiver(id, num_ots, 2, bitlen, p, data_storage, Send) {
    if (p == OTProtocol::ACOT &&
        (bitlen != 8u && bitlen != 16u && bitlen != 32u && bitlen != 64u)) {
      throw std::runtime_error(fmt::format(
          "Invalid parameter bitlen={}, only 8, 16, 32, or 64 are allowed in ACOT", bitlen_));
    }
    data_storage_->GetOTExtensionReceiverData()->num_messages_.emplace(id_, 1);
    if (p == OTProtocol::XCOT) {
      data_storage_->GetOTExtensionReceiverData()->xor_correlation_.emplace(id_);
    }
  }

  void SendCorrections() final {
    if (choices_.Empty()) {
      throw std::runtime_error("Choices in GOT must be set before calling SendCorrections()");
    }
    const auto &ote = data_storage_->GetOTExtensionReceiverData();
    auto corrections = choices_ ^ ote->random_choices_->Subset(id_, id_ + num_ots_);
    Send_(ABYN::Communication::BuildOTExtensionMessageReceiverCorrections(
        corrections.GetData().data(), corrections.GetData().size(), id_));
    corrections_sent_ = true;
  }

  void SetChoices(BitVector<> &&v) {
    choices_ = std::move(v);
    auto &ote = data_storage_->GetOTExtensionReceiverData();
    ote->real_choices_->Copy(id_, choices_);

    auto &cond = ote->real_choices_cond_.at(id_);
    {
      std::scoped_lock lock(cond->GetMutex());
      ote->set_real_choices_.emplace(id_);
    }
    cond->NotifyOne();
  }

  void SetChoices(const BitVector<> &v) {
    choices_ = v;
    auto &ote = data_storage_->GetOTExtensionReceiverData();
    ote->real_choices_->Copy(id_, choices_);

    auto &cond = ote->real_choices_cond_.at(id_);
    {
      std::scoped_lock lock(cond->GetMutex());
      ote->set_real_choices_.emplace(id_);
    }
    cond->NotifyOne();
  }

  const BitVector<> &GetChoices() final { return choices_; }

  const std::vector<BitVector<>> &GetOutputs() final {
    if (!corrections_sent_) {
      throw std::runtime_error("In COT, corrections must be set before calling GetOutputs()");
    }
    WaitSetup();
    auto &ote = data_storage_->GetOTExtensionReceiverData();
    ABYN::Helpers::WaitFor(*ote->output_conditions_.at(id_));

    if (messages_.empty()) {
      for (auto i = 0ull; i < num_ots_; ++i) {
        if (ote->outputs_.at(id_ + i).GetSize() > 0) {
          messages_.emplace_back(std::move(ote->outputs_.at(id_ + i)));
        }
      }
    }
    return messages_;
  }

 private:
  bool corrections_sent_ = false;
};

class ROTVectorReceiver final : public OTVectorReceiver {
 public:
  ROTVectorReceiver(const std::size_t id, const std::size_t num_ots, const std::size_t N,
                    const std::size_t bitlen,
                    const std::shared_ptr<ABYN::DataStorage> &data_storage,
                    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
      : OTVectorReceiver(id, num_ots, N, bitlen, OTProtocol::ROT, data_storage, Send) {
    Reserve(id, num_ots, bitlen);
  }

  void SetChoices([[maybe_unused]] const BitVector<> &v) final {
    throw std::runtime_error("Choices are random in ROT and thus cannot be set");
  }

  void SetChoices([[maybe_unused]] BitVector<> &&v) final {
    throw std::runtime_error("Choices are random in ROT and thus cannot be set");
  }

  void SendCorrections() final {
    throw std::runtime_error(
        "Choices are random in ROT and thus there is no need for correction bits");
  }

  const BitVector<> &GetChoices() final {
    WaitSetup();
    if (choices_.GetSize() == 0) {
      auto &ote = data_storage_->GetOTExtensionReceiverData();
      auto a_bv = ote->random_choices_->Subset(id_, id_ + num_ots_);
      choices_ = BitVector<>(a_bv.GetData().data(), a_bv.GetSize());
    }
    return choices_;
  }

  const std::vector<BitVector<>> &GetOutputs() final {
    WaitSetup();
    if (messages_.size() == 0) {
      auto &ote = data_storage_->GetOTExtensionReceiverData();
      auto data = ote->outputs_.begin();
      messages_.insert(messages_.end(), data + id_, data + id_ + num_ots_);
    }
    return messages_;
  }
};

class OTProviderSender {
 public:
  OTProviderSender() = default;

  OTProviderSender(const std::shared_ptr<ABYN::DataStorage> &data_storage)
      : data_storage_(data_storage) {}

  ~OTProviderSender() = default;

  OTProviderSender(const OTProviderSender &) = delete;

  std::shared_ptr<OTVectorSender> &GetOTs(std::size_t offset) {
    auto iterator = sender_data_.find(offset);
    if (iterator == sender_data_.end()) {
      throw std::runtime_error(fmt::format("Could not find an OTVector with offset {}", offset));
    }
    return iterator->second;
  };

  std::shared_ptr<OTVectorSender> &RegisterOTs(
      const std::size_t bitlen, const std::size_t num_ots, const std::size_t N, const OTProtocol p,
      const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send) {
    const auto i = total_ots_count_;
    total_ots_count_ += num_ots;
    std::shared_ptr<OTVectorSender> ot;
    switch (p) {
      case OTProtocol::GOT: {
        ot = std::make_shared<GOTVectorSender>(i, num_ots, N, bitlen, data_storage_, Send);
        break;
      }
      case OTProtocol::ACOT: {
        if (N != 2u) {
          throw std::runtime_error(
              fmt::format("Invalid parameter N={}, only 1-out-of-2 COT is allowed", N));
        }
        ot = std::make_shared<COTVectorSender>(i, num_ots, bitlen, p, data_storage_, Send);
        break;
      }
      case OTProtocol::XCOT: {
        if (N != 2u) {
          throw std::runtime_error(
              fmt::format("Invalid parameter N={}, only 1-out-of-2 COT is allowed", N));
        }
        ot = std::make_shared<COTVectorSender>(i, num_ots, bitlen, p, data_storage_, Send);
        break;
      }
      case OTProtocol::ROT: {
        ot = std::make_shared<ROTVectorSender>(i, num_ots, N, bitlen, data_storage_, Send);
        break;
      }
      default:
        throw std::runtime_error("Unknown OT protocol");
    }
    return sender_data_.insert(std::pair(i, ot)).first->second;
  }

  auto GetNumOTs() const { return total_ots_count_; }

 private:
  std::unordered_map<std::size_t, std::shared_ptr<OTVectorSender>> sender_data_;

  std::size_t total_ots_count_ = 0;

  std::shared_ptr<ABYN::DataStorage> data_storage_;
};

class OTProviderReceiver {
 public:
  OTProviderReceiver() = default;

  OTProviderReceiver(const std::shared_ptr<ABYN::DataStorage> &data_storage)
      : data_storage_(data_storage) {}

  ~OTProviderReceiver() = default;

  OTProviderReceiver(const OTProviderReceiver &) = delete;

  std::shared_ptr<OTVectorReceiver> &GetOTs(const std::size_t offset);

  std::shared_ptr<OTVectorReceiver> &RegisterOTs(
      const std::size_t bitlen, const std::size_t num_ots, const std::size_t N, const OTProtocol p,
      const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send) {
    const auto i = total_ots_count_;
    total_ots_count_ += num_ots;

    auto &data = data_storage_->GetOTExtensionReceiverData();

    if (p != OTProtocol::ROT) {
      {
        auto &&e =
            std::pair(i, std::make_unique<Condition>([this, i, &data]() {
                        return data->received_outputs_.find(i) != data->received_outputs_.end();
                      }));
        data->output_conditions_.insert(std::move(e));
      }
      {
        auto &&e =
            std::pair(i, std::make_unique<Condition>([this, i, &data]() {
                        return data->set_real_choices_.find(i) != data->set_real_choices_.end();
                      }));
        data->real_choices_cond_.insert(std::move(e));
      }
    }

    std::shared_ptr<OTVectorReceiver> ot;

    switch (p) {
      case OTProtocol::GOT: {
        ot = std::make_shared<GOTVectorReceiver>(i, num_ots, N, bitlen, data_storage_, Send);
        break;
      }
      case OTProtocol::XCOT: {
        if (N != 2u) {
          throw std::runtime_error(
              fmt::format("Invalid parameter N={}, only 1-out-of-2 COT is allowed", N));
        }
        ot = std::make_shared<COTVectorReceiver>(i, num_ots, bitlen, p, data_storage_, Send);
        break;
      }
      case OTProtocol::ACOT: {
        if (N != 2u) {
          throw std::runtime_error(
              fmt::format("Invalid parameter N={}, only 1-out-of-2 COT is allowed", N));
        }
        ot = std::make_shared<COTVectorReceiver>(i, num_ots, bitlen, p, data_storage_, Send);
        break;
      }
      case OTProtocol::ROT: {
        ot = std::make_shared<ROTVectorReceiver>(i, num_ots, N, bitlen, data_storage_, Send);
        break;
      }
      default:
        throw std::runtime_error("Unknown OT protocol");
    }
    auto &&e = std::pair(i, ot);
    return receiver_data_.insert(std::move(e)).first->second;
  }

  std::size_t GetNumOTs() const { return total_ots_count_; }

 private:
  std::unordered_map<std::size_t, std::shared_ptr<OTVectorReceiver>> receiver_data_;

  std::size_t total_ots_count_ = 0;

  std::shared_ptr<ABYN::DataStorage> data_storage_;
};

// OTProvider encapsulates both sender and receiver interfaces for simplicity
class OTProvider {
 public:
  virtual ~OTProvider() = default;

  OTProvider(const OTProvider &) = delete;

  /// @param N Number of messages in the OT (i.e., N in 1-out-of-N)
  /// @param bitlen Bit-length of the messages
  /// @param num_ots Number of OTs
  /// @param p OT protocol from {General OT (GOT), Correlated OT (COT), Random OT (ROT)}
  /// @return Offset to the OT that can be used to set input messages
  std::shared_ptr<OTVectorSender> &RegisterSend(const std::size_t bitlen = 1,
                                                const std::size_t num_ots = 1,
                                                const std::size_t N = 2, const OTProtocol p = GOT) {
    return sender_provider_.RegisterOTs(bitlen, num_ots, N, p, Send_);
  }

  /// @param N Number of messages in the OT (i.e., N in 1-out-of-N)
  /// @param bitlen Bit-length of the messages
  /// @param num_ots Number of OTs
  /// @param p OT protocol from {General OT (GOT), Correlated OT (COT), Random OT (ROT)}
  /// @return Offset to the OT that can be used to retrieve the output of the OT
  std::shared_ptr<OTVectorReceiver> &RegisterReceive(const std::size_t bitlen = 1,
                                                     const std::size_t num_ots = 1,
                                                     const std::size_t N = 2,
                                                     const OTProtocol p = GOT) {
    return receiver_provider_.RegisterOTs(bitlen, num_ots, N, p, Send_);
  }

  std::shared_ptr<OTVectorSender> &GetSent(const size_t id) { return sender_provider_.GetOTs(id); }

  std::shared_ptr<OTVectorReceiver> &GetReceiver(const size_t id) {
    return receiver_provider_.GetOTs(id);
  }

  virtual void SendSetup() = 0;
  virtual void ReceiveSetup() = 0;

 protected:
  OTProvider(const std::shared_ptr<ABYN::DataStorage> &data_storage,
             std::function<void(flatbuffers::FlatBufferBuilder &&)> Send)
      : data_storage_(data_storage),
        Send_(Send),
        receiver_provider_(OTProviderReceiver(data_storage_)),
        sender_provider_(OTProviderSender(data_storage_)) {}

  std::shared_ptr<ABYN::DataStorage> data_storage_;
  std::function<void(flatbuffers::FlatBufferBuilder &&)> Send_;
  OTProviderReceiver receiver_provider_;
  OTProviderSender sender_provider_;
};

class OTProviderFromFile : public OTProvider {
  // TODO
};

class OTProviderFromBaseOTs : public OTProvider {
  // TODO
};

class OTProviderFromOTExtension final : public OTProvider {
 public:
  void SendSetup() final;

  void ReceiveSetup() final;

  OTProviderFromOTExtension(std::function<void(flatbuffers::FlatBufferBuilder &&)> Send,
                            const std::shared_ptr<ABYN::DataStorage> &data_storage)
      : OTProvider(data_storage, Send){};
};

class OTProviderFromThirdParty : public OTProvider {
  // TODO
};

class OTProviderFromMultipleThirdParties : public OTProvider {
  // TODO
};

}  // namespace ObliviousTransfer
}