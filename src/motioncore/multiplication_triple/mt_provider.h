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

#include <list>

#include "oblivious_transfer/ot_flavors.h"
#include "utility/bit_vector.h"
#include "utility/fiber_condition.h"
#include "utility/helpers.h"

namespace encrypto::motion {

struct RunTimeStatistics;
class Logger;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
struct IntegerMtVector {
  std::vector<T> a, b, c;  // c[i] = a[i] * b[i]
};

struct BinaryMtVector {
  BitVector<> a, b, c;  // c[i] = a[i] ^ b[i]
};

class MtProvider {
 public:
  virtual ~MtProvider() = default;

  bool NeedMts() const noexcept;

  template <typename T>
  std::size_t GetNumberOfMts() const noexcept {
    if constexpr (std::is_same_v<T, bool>) {
      return number_of_bit_mts_;
    } else if constexpr (std::is_same_v<T, std::uint8_t>) {
      return number_of_mts_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return number_of_mts_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return number_of_mts_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return number_of_mts_64_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  std::size_t RequestBinaryMts(const std::size_t number_of_mts) noexcept;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::size_t RequestArithmeticMts(const std::size_t number_of_mts) noexcept {
    std::size_t offset;
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      offset = number_of_mts_8_;
      number_of_mts_8_ += number_of_mts;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      offset = number_of_mts_16_;
      number_of_mts_16_ += number_of_mts;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      offset = number_of_mts_32_;
      number_of_mts_32_ += number_of_mts;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      offset = number_of_mts_64_;
      number_of_mts_64_ += number_of_mts;
    } else {
      throw std::runtime_error("Unknown type");
    }
    return offset;
  }

  // get bits [i, i+n] as vector
  BinaryMtVector GetBinary(const std::size_t offset, const std::size_t n = 1) const;

  const BinaryMtVector& GetBinaryAll() const noexcept;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  IntegerMtVector<T> GetInteger(const std::size_t offset, const std::size_t n = 1) const {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return GetInteger(mts8_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return GetInteger(mts16_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return GetInteger(mts32_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return GetInteger(mts64_, offset, n);
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  const IntegerMtVector<T>& GetIntegerAll() const noexcept {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return mts8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return mts16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return mts32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return mts64_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  virtual void PreSetup() = 0;
  virtual void Setup() = 0;

  // blocking wait
  void WaitFinished() const { finished_condition_->Wait(); }

 protected:
  MtProvider(std::size_t my_id, std::size_t number_of_parties);
  MtProvider() = delete;

  std::size_t number_of_bit_mts_{0}, number_of_mts_8_{0}, number_of_mts_16_{0},
      number_of_mts_32_{0}, number_of_mts_64_{0};

  BinaryMtVector bit_mts_;

  IntegerMtVector<std::uint8_t> mts8_;
  IntegerMtVector<std::uint16_t> mts16_;
  IntegerMtVector<std::uint32_t> mts32_;
  IntegerMtVector<std::uint64_t> mts64_;

  const std::size_t my_id_;
  const std::size_t number_of_parties_;

  std::atomic<bool> finished_{false};
  std::shared_ptr<FiberCondition> finished_condition_;

 private:
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline IntegerMtVector<T> GetInteger(const IntegerMtVector<T>& mts, const std::size_t offset,
                                       const std::size_t n) const {
    assert(mts.a.size() == mts.b.size());
    assert(mts.c.size() == mts.b.size());
    assert(offset + n <= mts.a.size());

    return IntegerMtVector<T>{std::vector<T>(mts.a.begin() + offset, mts.a.begin + offset + n),
                              std::vector<T>(mts.b.begin() + offset, mts.b.begin + offset + n),
                              std::vector<T>(mts.c.begin() + offset, mts.c.begin + offset + n)};
  }
};

class MtProviderFromOts final : public MtProvider {
 public:
  MtProviderFromOts(std::vector<std::unique_ptr<OtProvider>>& ot_providers, const std::size_t my_id,
                    std::shared_ptr<Logger> logger, RunTimeStatistics& run_time_statistics);
  ~MtProviderFromOts();

  void PreSetup() final override;

  // needs completed OTExtension
  void Setup() final override;

 private:
  void RegisterOts();

  void ParseOutputs();

  std::vector<std::unique_ptr<OtProvider>>& ot_providers_;

  // use alternating party roles for load balancing
  std::vector<std::list<std::unique_ptr<BasicOtReceiver>>> ots_receiver_8_;
  std::vector<std::list<std::unique_ptr<BasicOtSender>>> ots_sender_8_;

  std::vector<std::list<std::unique_ptr<BasicOtReceiver>>> ots_receiver_16_;
  std::vector<std::list<std::unique_ptr<BasicOtSender>>> ots_sender_16_;

  std::vector<std::list<std::unique_ptr<BasicOtReceiver>>> ots_receiver_32_;
  std::vector<std::list<std::unique_ptr<BasicOtSender>>> ots_sender_32_;

  std::vector<std::list<std::unique_ptr<BasicOtReceiver>>> ots_receiver_64_;
  std::vector<std::list<std::unique_ptr<BasicOtSender>>> ots_sender_64_;

  std::vector<std::unique_ptr<XcOtBitReceiver>> bit_ots_receiver_;
  std::vector<std::unique_ptr<XcOtBitSender>> bit_ots_sender_;

  // Should be divisible by 128
  static inline constexpr std::size_t kMaxBatchSize{128 * 128};

  std::shared_ptr<Logger> logger_;
  RunTimeStatistics& run_time_statistics_;
};

}  // namespace encrypto::motion
