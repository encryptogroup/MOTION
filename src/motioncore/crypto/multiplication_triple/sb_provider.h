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

#include "utility/condition.h"
#include "utility/reusable_future.h"

namespace MOTION {

namespace Statistics {
struct RunTimeStats;
}

class Configuration;
class Register;
class SPProvider;

// Provider for Shared Bits (SBs),
// sharings of a random bit 0 or 1 in Z/2^kZ
class SBProvider {
 public:
  bool NeedSBs() const noexcept;

  template <typename T>
  std::size_t GetNumSBs() const noexcept {
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return num_sbs_8_;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return num_sbs_16_;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return num_sbs_32_;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return num_sbs_64_;
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::size_t RequestSBs(const std::size_t num_sbs) noexcept {
    std::size_t offset;
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      offset = num_sbs_8_;
      num_sbs_8_ += num_sbs;
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      offset = num_sbs_16_;
      num_sbs_16_ += num_sbs;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      offset = num_sbs_32_;
      num_sbs_32_ += num_sbs;
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      offset = num_sbs_64_;
      num_sbs_64_ += num_sbs;
    } else {
      throw std::runtime_error("Unknown type");
    }
    return offset;
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::vector<T> GetSBs(const std::size_t offset, const std::size_t n = 1) {
    WaitFinished();
    if constexpr (std::is_same_v<T, std::uint8_t>) {
      return GetSBs(sbs_8_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint16_t>) {
      return GetSBs(sbs_16_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
      return GetSBs(sbs_32_, offset, n);
    } else if constexpr (std::is_same_v<T, std::uint64_t>) {
      return GetSBs(sbs_64_, offset, n);
    } else {
      throw std::runtime_error("Unknown type");
    }
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  const std::vector<T>& GetSBsAll() noexcept {
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
  SBProvider(const std::size_t my_id);
  SBProvider() = delete;

  std::size_t num_sbs_8_{0}, num_sbs_16_{0}, num_sbs_32_{0}, num_sbs_64_{0};

  std::vector<std::uint8_t> sbs_8_;
  std::vector<std::uint16_t> sbs_16_;
  std::vector<std::uint32_t> sbs_32_;
  std::vector<std::uint64_t> sbs_64_;

  const std::size_t my_id_;

  bool finished_ = false;
  std::shared_ptr<ENCRYPTO::Condition> finished_condition_;

 private:
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline std::vector<T> GetSBs(const std::vector<T>& sbs, const std::size_t offset,
                               const std::size_t n) const {
    assert(offset + n <= sbs.size());
    return std::vector(sbs.cbegin() + offset, sbs.cbegin() + offset + n);
  }
};

class SBProviderFromSPs final : public SBProvider {
 public:
  SBProviderFromSPs(std::shared_ptr<Configuration> config, std::shared_ptr<Register> _register,
                    std::shared_ptr<SPProvider> sp_provider,
                    Statistics::RunTimeStats& run_time_stats);

  void PreSetup() final;

  // needs completed SPs
  void Setup() final;

 private:
  void RegisterSPs();
  void RegisterForMessages();
  void ComputeSBs() noexcept;

  // void reconstruct_helper(
  //     std::vector<std::uint16_t>& ds_8, std::vector<std::uint32_t>& ds_16,
  //     std::vector<std::uint64_t>& ds_32,
  //     std::function<void(std::size_t, const std::vector<uint8_t>&)> send_fctn,
  //     std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>>& futures);

  void ParseOutputs();

  std::shared_ptr<Configuration> config_;
  std::shared_ptr<Register> register_;
  std::shared_ptr<SPProvider> sp_provider_;

  std::size_t offset_sps_16_;
  std::size_t offset_sps_32_;
  std::size_t offset_sps_64_;
  std::size_t offset_sps_128_;

  std::vector<ENCRYPTO::ReusableFuture<std::vector<uint8_t>>> mask_message_futures_;
  std::vector<ENCRYPTO::ReusableFuture<std::vector<uint8_t>>> reconstruct_message_futures_;

  const std::size_t max_batch_size_{10'000};

  Statistics::RunTimeStats& run_time_stats_;
};

}  // namespace MOTION
