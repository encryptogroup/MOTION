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
#include <memory>
#include <type_traits>
#include <vector>

#include "utility/fiber_condition.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion {

class Logger;
class SpProvider;
struct RunTimeStatistics;
struct SharedBitsData;

// Provider for Shared Bits (SBs),
// sharings of a random bit 0 or 1 in Z/2^kZ
class SbProvider {
 public:
  bool NeedSbs() const noexcept;

  template <typename T>
  std::size_t GetNumberOfSbs() const noexcept {
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return number_of_sbs_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return number_of_sbs_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return number_of_sbs_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return number_of_sbs_64_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::size_t RequestSbs(const std::size_t number_of_sbs) noexcept {
    std::size_t offset;
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      offset = number_of_sbs_8_;
      number_of_sbs_8_ += number_of_sbs;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      offset = number_of_sbs_16_;
      number_of_sbs_16_ += number_of_sbs;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      offset = number_of_sbs_32_;
      number_of_sbs_32_ += number_of_sbs;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      offset = number_of_sbs_64_;
      number_of_sbs_64_ += number_of_sbs;
    } else {
      throw std::runtime_error("Unknown type");
    }
    return offset;
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::vector<T> GetSbs(const std::size_t offset, const std::size_t n = 1) {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return GetSbs(sbs_8_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return GetSbs(sbs_16_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return GetSbs(sbs_32_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return GetSbs(sbs_64_, offset, n);
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  const std::vector<T>& GetSbsAll() noexcept {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return sbs_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return sbs_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return sbs_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return sbs_64_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  virtual void PreSetup() = 0;
  virtual void Setup() = 0;

  // blocking wait
  void WaitFinished() { finished_condition_->Wait(); }

 protected:
  SbProvider(const std::size_t my_id);
  SbProvider() = delete;

  std::size_t number_of_sbs_8_{0}, number_of_sbs_16_{0}, number_of_sbs_32_{0}, number_of_sbs_64_{0};

  std::vector<std::uint8_t> sbs_8_;
  std::vector<std::uint16_t> sbs_16_;
  std::vector<std::uint32_t> sbs_32_;
  std::vector<std::uint64_t> sbs_64_;

  const std::size_t my_id_;

  bool finished_ = false;
  std::shared_ptr<FiberCondition> finished_condition_;

 private:
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline std::vector<T> GetSbs(const std::vector<T>& sbs, const std::size_t offset,
                               const std::size_t n) const {
    assert(offset + n <= sbs.size());
    return std::vector(sbs.cbegin() + offset, sbs.cbegin() + offset + n);
  }
};

class SbProviderFromSps final : public SbProvider {
 public:
  SbProviderFromSps(communication::CommunicationLayer& communication_layer,
                    std::shared_ptr<SpProvider> sp_provider, std::shared_ptr<Logger> logger,
                    RunTimeStatistics& run_time_statistics);
  ~SbProviderFromSps();

  void PreSetup() final override;

  // needs completed SPs
  void Setup() final override;

 private:
  void RegisterSps();
  void RegisterForMessages();
  void ComputeSbs() noexcept;

  void ParseOutputs();

  communication::CommunicationLayer& communication_layer_;
  std::size_t number_of_parties_;
  std::shared_ptr<SpProvider> sp_provider_;

  std::size_t offset_sps_16_;
  std::size_t offset_sps_32_;
  std::size_t offset_sps_64_;
  std::size_t offset_sps_128_;

  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> mask_message_futures_;
  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> reconstruct_message_futures_;

  const std::size_t kMaxBatchSize{10'000};

  std::shared_ptr<Logger> logger_;
  RunTimeStatistics& run_time_statistics_;
};

}  // namespace encrypto::motion
