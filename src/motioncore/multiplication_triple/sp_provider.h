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

#include "oblivious_transfer/ot_flavors.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

class OtProvider;
class OtVectorSender;
class OtVectorReceiver;
struct RunTimeStatistics;
class Logger;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
struct SpVector {
  std::vector<T> a, c;  // c[i] = a[i]^2
};

// Provider for Square Pairs (SPs),
// sharings of random (a, c) s.t. a^2 = c
class SpProvider {
 public:
  virtual ~SpProvider() = default;

  bool NeedSps() const noexcept;

  template <typename T>
  std::size_t GetNumberOfSps() const noexcept {
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return number_of_sps_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return number_of_sps_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return number_of_sps_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return number_of_sps_64_;
    } else if constexpr (std::is_same_v<T, __uint128_t>) {
      return number_of_sps_128_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::size_t RequestSps(const std::size_t number_of_sps) noexcept {
    std::size_t offset;
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      offset = number_of_sps_8_;
      number_of_sps_8_ += number_of_sps;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      offset = number_of_sps_16_;
      number_of_sps_16_ += number_of_sps;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      offset = number_of_sps_32_;
      number_of_sps_32_ += number_of_sps;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      offset = number_of_sps_64_;
      number_of_sps_64_ += number_of_sps;
    } else if constexpr (std::is_same_v<T, __uint128_t>) {
      offset = number_of_sps_128_;
      number_of_sps_128_ += number_of_sps;
    } else {
      throw std::runtime_error("Unknown type");
    }
    return offset;
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SpVector<T> GetSps(const std::size_t offset, const std::size_t n = 1) {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return GetSps(sps_8_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return GetSps(sps_16_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return GetSps(sps_32_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return GetSps(sps_64_, offset, n);
    } else if constexpr (std::is_same_v<T, __uint128_t>) {
      return GetSps(sps_128_, offset, n);
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  const SpVector<T>& GetSpsAll() noexcept {
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
  SpProvider(const std::size_t my_id);
  SpProvider() = delete;

  std::size_t number_of_sps_8_{0}, number_of_sps_16_{0}, number_of_sps_32_{0}, number_of_sps_64_{0},
      number_of_sps_128_{0};

  SpVector<std::uint8_t> sps_8_;
  SpVector<std::uint16_t> sps_16_;
  SpVector<std::uint32_t> sps_32_;
  SpVector<std::uint64_t> sps_64_;
  SpVector<__uint128_t> sps_128_;

  const std::size_t my_id_;

  bool finished_ = false;
  std::shared_ptr<FiberCondition> finished_condition_;

 private:
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline SpVector<T> GetSps(const SpVector<T>& sps, const std::size_t offset,
                            const std::size_t n) const {
    assert(sps.a.size() == sps.c.size());
    assert(offset + n <= sps.a.size());

    return SpVector<T>{std::vector<T>(sps.a.begin() + offset, sps.a.begin() + offset + n),
                       std::vector<T>(sps.c.begin() + offset, sps.c.begin() + offset + n)};
  }
};

class SpProviderFromOts final : public SpProvider {
 public:
  SpProviderFromOts(std::vector<std::unique_ptr<OtProvider>>& ot_providers, const std::size_t my_id,
                    std::shared_ptr<Logger> logger, RunTimeStatistics& run_time_statistics);

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

  std::vector<std::list<std::unique_ptr<BasicOtReceiver>>> ots_receiver_128_;
  std::vector<std::list<std::unique_ptr<BasicOtSender>>> ots_sender_128_;

  const std::size_t kMaxBatchSize{10'000};

  std::shared_ptr<Logger> logger_;
  RunTimeStatistics& run_time_statistics_;
};

}  // namespace encrypto::motion
