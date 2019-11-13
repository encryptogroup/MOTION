// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include <cstdint>
#include <list>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "utility/condition.h"

namespace ENCRYPTO {
namespace ObliviousTransfer {
class OTProvider;
class OTVectorSender;
class OTVectorReceiver;
}  // namespace ObliviousTransfer
}  // namespace ENCRYPTO

namespace MOTION {

namespace Statistics {
struct RunTimeStats;
}

class Logger;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
struct SPVector {
  std::vector<T> a, c;  // c[i] = a[i]^2
};

// Provider for Square Pairs (SPs),
// sharings of random (a, c) s.t. a^2 = c
class SPProvider {
 public:
  bool NeedSPs() const noexcept;

  template <typename T>
  std::size_t GetNumSPs() const noexcept {
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return num_sps_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return num_sps_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return num_sps_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return num_sps_64_;
    } else if constexpr (std::is_same_v<T, __uint128_t>) {
      return num_sps_128_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::size_t RequestSPs(const std::size_t num_sps) noexcept {
    std::size_t offset;
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      offset = num_sps_8_;
      num_sps_8_ += num_sps;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      offset = num_sps_16_;
      num_sps_16_ += num_sps;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      offset = num_sps_32_;
      num_sps_32_ += num_sps;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      offset = num_sps_64_;
      num_sps_64_ += num_sps;
    } else if constexpr (std::is_same_v<T, __uint128_t>) {
      offset = num_sps_128_;
      num_sps_128_ += num_sps;
    } else {
      throw std::runtime_error("Unknown type");
    }
    return offset;
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SPVector<T> GetSPs(const std::size_t offset, const std::size_t n = 1) {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return GetSPs(sps_8_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return GetSPs(sps_16_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return GetSPs(sps_32_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return GetSPs(sps_64_, offset, n);
    } else if constexpr (std::is_same_v<T, __uint128_t>) {
      return GetSPs(sps_128_, offset, n);
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  const SPVector<T>& GetSPsAll() noexcept {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return sps_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return sps_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return sps_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return sps_64_;
    } else if constexpr (std::is_same_v<T, __uint128_t>) {
      return sps_128_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  virtual void PreSetup() = 0;
  virtual void Setup() = 0;

  // blocking wait
  void WaitFinished() { finished_condition_->Wait(); }

 protected:
  SPProvider(const std::size_t my_id);
  SPProvider() = delete;

  std::size_t num_sps_8_{0}, num_sps_16_{0}, num_sps_32_{0}, num_sps_64_{0}, num_sps_128_{0};

  SPVector<std::uint8_t> sps_8_;
  SPVector<std::uint16_t> sps_16_;
  SPVector<std::uint32_t> sps_32_;
  SPVector<std::uint64_t> sps_64_;
  SPVector<__uint128_t> sps_128_;

  const std::size_t my_id_;

  bool finished_ = false;
  std::shared_ptr<ENCRYPTO::Condition> finished_condition_;

 private:
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline SPVector<T> GetSPs(const SPVector<T>& sps, const std::size_t offset,
                            const std::size_t n) const {
    assert(sps.a.size() == sps.c.size());
    assert(offset + n <= sps.a.size());

    return SPVector<T>{std::vector<T>(sps.a.begin() + offset, sps.a.begin() + offset + n),
                       std::vector<T>(sps.c.begin() + offset, sps.c.begin() + offset + n)};
  }
};

class SPProviderFromOTs final : public SPProvider {
 public:
  SPProviderFromOTs(
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

  const std::size_t max_batch_size_{10'000};

  Logger& logger_;
  Statistics::RunTimeStats& run_time_stats_;
};

}  // namespace MOTION
