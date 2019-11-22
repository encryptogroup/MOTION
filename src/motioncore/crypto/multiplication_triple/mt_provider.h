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

#include "crypto/oblivious_transfer/ot_provider.h"
#include "utility/bit_vector.h"
#include "utility/condition.h"
#include "utility/helpers.h"

namespace MOTION {

namespace Statistics {
struct RunTimeStats;
}

class Logger;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
struct IntegerMTVector {
  std::vector<T> a, b, c;  // c[i] = a[i] * b[i]
};

struct BinaryMTVector {
  ENCRYPTO::BitVector<> a, b, c;  // c[i] = a[i] ^ b[i]
};

class MTProvider {
 public:
  bool NeedMTs() const noexcept;

  template <typename T>
  std::size_t GetNumMTs() const noexcept {
    if constexpr (std::is_same_v<T, bool>) {
      return num_bit_mts_;
    } else if constexpr (std::is_same_v<T, std::uint8_t>) {
      return num_mts_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return num_mts_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return num_mts_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return num_mts_64_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  std::size_t RequestBinaryMTs(const std::size_t num_mts) noexcept;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::size_t RequestArithmeticMTs(const std::size_t num_mts) noexcept {
    std::size_t offset;
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      offset = num_mts_8_;
      num_mts_8_ += num_mts;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      offset = num_mts_16_;
      num_mts_16_ += num_mts;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      offset = num_mts_32_;
      num_mts_32_ += num_mts;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      offset = num_mts_64_;
      num_mts_64_ += num_mts;
    } else {
      throw std::runtime_error("Unknown type");
    }
    return offset;
  }

  // get bits [i, i+n] as vector
  BinaryMTVector GetBinary(const std::size_t offset, const std::size_t n = 1);

  const BinaryMTVector& GetBinaryAll() noexcept;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  IntegerMTVector<T> GetInteger(const std::size_t offset, const std::size_t n = 1) {
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
  const IntegerMTVector<T>& GetIntegerAll() noexcept {
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
  void WaitFinished() { MOTION::Helpers::WaitFor(*finished_condition_); }

 protected:
  MTProvider(const std::size_t my_id);
  MTProvider() = delete;

  std::size_t num_bit_mts_{0}, num_mts_8_{0}, num_mts_16_{0}, num_mts_32_{0}, num_mts_64_{0};

  BinaryMTVector bit_mts_;

  IntegerMTVector<std::uint8_t> mts8_;
  IntegerMTVector<std::uint16_t> mts16_;
  IntegerMTVector<std::uint32_t> mts32_;
  IntegerMTVector<std::uint64_t> mts64_;

  const std::size_t my_id_;

  std::atomic<bool> finished_{false};
  std::shared_ptr<ENCRYPTO::Condition> finished_condition_;

 private:
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline IntegerMTVector<T> GetInteger(const IntegerMTVector<T>& mts, const std::size_t offset,
                                       const std::size_t n) const {
    assert(mts.a.size() == mts.b.size());
    assert(mts.c.size() == mts.b.size());
    assert(offset + n <= mts.a.size());

    return IntegerMTVector<T>{std::vector<T>(mts.a.begin() + offset, mts.a.begin + offset + n),
                              std::vector<T>(mts.b.begin() + offset, mts.b.begin + offset + n),
                              std::vector<T>(mts.c.begin() + offset, mts.c.begin + offset + n)};
  }
};

class MTProviderFromOTs final : public MTProvider {
 public:
  MTProviderFromOTs(
      std::vector<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTProvider>>& ot_providers,
      const std::size_t my_id, Logger& logger, Statistics::RunTimeStats& run_time_stats);

  void PreSetup() final;

  // needs completed OTExtension
  void Setup() final;

 private:
  void RegisterOTs();

  void ParseOutputs();

  std::vector<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTProvider>>& ot_providers_;

  // use alternating party roles for load balancing
  std::vector<std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>>> ots_rcv_;
  std::vector<std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>>> ots_snd_;

  // divisible by 128
  static inline constexpr std::size_t max_batch_size_{16'384};

  Logger& logger_;
  Statistics::RunTimeStats& run_time_stats_;
};

}  // namespace MOTION
