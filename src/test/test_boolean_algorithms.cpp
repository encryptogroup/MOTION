// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko
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

#include <gtest/gtest.h>

#include <bit>
#include <chrono>
#include <iterator>

#include "algorithm/boolean_algorithms.h"
#include "base/party.h"
#include "protocols/garbled_circuit/garbled_circuit_constants.h"
#include "protocols/garbled_circuit/garbled_circuit_provider.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"
#include "utility/reusable_future.h"

namespace {

constexpr std::size_t kNumberOfParallelTests = 100;

class BooleanAlgorithmTest : public testing::Test {
 public:
  void SetUp() override { parties_ = MakeParties(); }

  std::vector<encrypto::motion::PartyPointer> MakeParties() {
    auto parties{encrypto::motion::MakeLocallyConnectedParties(2, kPortOffset)};
    for (auto& party : parties_) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    return parties;
  }

  encrypto::motion::BitVector<> GenerateRandomBitVector(std::size_t bitlength) {
    return encrypto::motion::BitVector<>::RandomSeeded(1, this->bitvector_randomness_seed_++);
  }

  std::pair<std::vector<std::uint8_t>, std::vector<std::vector<encrypto::motion::BitVector<>>>>
  GenerateInputsForAllPossibleInputs(std::size_t bit_length) {
    assert(bit_length <= 8u);
    std::size_t number_of_elements{std::size_t(1) << bit_length};

    std::vector<std::uint8_t> values(number_of_elements);
    std::vector<std::vector<encrypto::motion::BitVector<>>> inputs;
    std::generate(values.begin(), values.end(), [i = 0]() mutable { return i++; });
    inputs.resize(number_of_elements);
    for (std::size_t value_i = 0; value_i < inputs.size(); ++value_i) {
      auto bit_length = values[value_i] == 0
                            ? 1
                            : static_cast<std::size_t>(std::ceil(std::log2(values[value_i]))) + 1;
      assert(bit_length > 0);
      inputs[value_i].resize(bit_length);
      for (std::size_t bit_j = 0; bit_j < bit_length; ++bit_j) {
        bool extracted_bit{((values[value_i] >> bit_j) & 1) == 1};
        inputs[value_i][bit_j].Append(extracted_bit);
      }
    }
    return std::pair(values, inputs);
  }

 protected:
  bool online_after_setup_ = false;
  std::vector<encrypto::motion::PartyPointer> parties_;
  std::size_t bitvector_randomness_seed_ = 0;
  static constexpr auto garbler_id_{
      static_cast<std::size_t>(encrypto::motion::GarbledCircuitRole::kGarbler)};
  static constexpr std::size_t evaluator_id_{1 - garbler_id_};
};

class FullAdderTest : public BooleanAlgorithmTest {
 public:
  void GenerateInputsForFullAdder() {
    global_inputs_.resize(3);
    std::byte a{0b11110000};
    global_inputs_[0].Append(&a, 8);
    std::byte b{0b11001100};
    global_inputs_[1].Append(&b, 8);
    std::byte carry{0b10101010};
    global_inputs_[2].Append(&carry, 8);
  }
  std::vector<encrypto::motion::BitVector<>> global_inputs_;
};

TEST_F(FullAdderTest, AllInputCombinations) {
  this->GenerateInputsForFullAdder();
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      auto [input_share_0, input_promise_0] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(0, 1, 8);
      auto [input_share_1, input_promise_1] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(0, 1, 8);
      auto [input_share_2, input_promise_2] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(0, 1, 8);

      encrypto::motion::ShareWrapper input_0(input_share_0), input_1(input_share_1),
          input_2(input_share_2);
      // Set inputs using the obtained promise
      if (party_id == this->garbler_id_) {
        input_promise_0->set_value({this->global_inputs_[0]});
        input_promise_1->set_value({this->global_inputs_[1]});
        input_promise_2->set_value({this->global_inputs_[2]});
      }

      auto [sum, carry] = encrypto::motion::algorithm::FullAdder(input_0, input_1, input_2);

      auto output_sum{sum.Out()};
      auto output_carry{carry.Out()};
      this->parties_[party_id]->Run();

      auto sum_plain{output_sum.As<encrypto::motion::BitVector<>>()};
      auto carry_plain{output_carry.As<encrypto::motion::BitVector<>>()};

      for (std::size_t i = 0; i < 8u; ++i) {
        ASSERT_EQ(
            this->global_inputs_[0][i] != this->global_inputs_[1][i] != this->global_inputs_[2][i],
            sum_plain[i])
            << fmt::format("Inputs: a={} b={} carry={}", this->global_inputs_[0][i],
                           this->global_inputs_[1][i], this->global_inputs_[2][i]);
        EXPECT_EQ((this->global_inputs_[0][i] && this->global_inputs_[1][i]) ||
                      (this->global_inputs_[0][i] && this->global_inputs_[2][i]) ||
                      (this->global_inputs_[1][i] && this->global_inputs_[2][i]),
                  carry_plain[i])
            << fmt::format("Inputs: a={} b={} carry={}", this->global_inputs_[0][i],
                           this->global_inputs_[1][i], this->global_inputs_[2][i]);
      }

      this->parties_[party_id]->Finish();
    }));
  }

  for (auto& f : futures) f.get();
}

class AdderChainTest : public BooleanAlgorithmTest {
 public:
  void GenerateInputsForAdderChain() {
    std::tie(values_, global_inputs_) = GenerateInputsForAllPossibleInputs(kBitLength);
  }

  static constexpr std::size_t kBitLength{5}, kNumberOfValues{1 << kBitLength};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_inputs_;
  std::vector<std::uint8_t> values_;
};

TEST_F(AdderChainTest, FiveBitsAllCombinations) {
  this->GenerateInputsForAdderChain();
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      std::vector<encrypto::motion::ShareWrapper> input_shares(kNumberOfValues);
      std::vector<
          encrypto::motion::ReusableFiberPromise<std::vector<encrypto::motion::BitVector<>>>*>
          input_promises(kNumberOfValues);
      for (std::size_t i = 0; i < kNumberOfValues; ++i) {
        std::tie(input_shares[i], input_promises[i]) =
            this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
                0, this->global_inputs_[i].size(), 1);
      }

      auto [zero_share, zero_promise] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(0, 1, 1);
      auto [one_share, one_promise] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(0, 1, 1);

      // Set inputs using the obtained promise
      if (party_id == this->garbler_id_) {
        for (std::size_t i = 0; i < kNumberOfValues; ++i) {
          input_promises[i]->set_value(this->global_inputs_[i]);
        }
        zero_promise->set_value({encrypto::motion::BitVector<>(1, false)});
        one_promise->set_value({encrypto::motion::BitVector<>(1, true)});
      }

      std::vector<encrypto::motion::ShareWrapper> results;
      results.reserve(2 * this->values_.size() * this->values_.size());
      for (auto& carry : {encrypto::motion::ShareWrapper(zero_share),
                          encrypto::motion::ShareWrapper(one_share)}) {
        for (std::size_t i = 0; i < this->values_.size(); ++i) {
          for (std::size_t j = 0; j < this->values_.size(); ++j) {
            results.emplace_back(
                encrypto::motion::algorithm::AdderChain(input_shares[i], input_shares[j], carry));
          }
        }
      }

      std::vector<encrypto::motion::ShareWrapper> output_results(results.size());
      std::transform(results.begin(), results.end(), output_results.begin(),
                     [](const auto& share) { return share.Out(); });

      this->parties_[party_id]->Run();

      for (std::uint8_t carry : {0, 1}) {
        for (std::size_t i = 0; i < this->values_.size(); ++i) {
          for (std::size_t j = 0; j < this->values_.size(); ++j) {
            auto computed_bvs = output_results[carry * this->values_.size() * this->values_.size() +
                                               i * this->values_.size() + j]
                                    .As<std::vector<encrypto::motion::BitVector<>>>();
            std::uint8_t computed_value{0};
            for (std::size_t bit_k = 0; bit_k < computed_bvs.size(); ++bit_k) {
              if (computed_bvs[bit_k][0]) computed_value += std::uint8_t(1) << bit_k;
            }
            std::uint8_t expected_value = this->values_[i] + this->values_[j] + carry;
            EXPECT_EQ(computed_value, expected_value);

            std::size_t expected_length{
                std::max(this->global_inputs_[i].size(), this->global_inputs_[j].size()) + 1};
            EXPECT_EQ(expected_length, computed_bvs.size());
          }
        }
      }

      this->parties_[party_id]->Finish();
    }));
  }

  for (auto& f : futures) f.get();
}

class HammingWeightTest : public BooleanAlgorithmTest {
 public:
  void GenerateInputsForHammingWeight() {
    std::tie(values_, global_inputs_) = GenerateInputsForAllPossibleInputs(kBitLength);
  }

  static constexpr std::size_t kBitLength{8}, kNumberOfValues{1 << kBitLength};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_inputs_;
  std::vector<std::uint8_t> values_;
};

TEST_F(HammingWeightTest, EightBitsAllPossibleInputs) {
  this->GenerateInputsForHammingWeight();
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      std::vector<encrypto::motion::ShareWrapper> input_shares(kNumberOfValues);
      std::vector<
          encrypto::motion::ReusableFiberPromise<std::vector<encrypto::motion::BitVector<>>>*>
          input_promises(kNumberOfValues);
      for (std::size_t i = 0; i < kNumberOfValues; ++i) {
        std::tie(input_shares[i], input_promises[i]) =
            this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
                0, this->global_inputs_[i].size(), 1);
      }

      // Set inputs using the obtained promise
      if (party_id == this->garbler_id_) {
        for (std::size_t i = 0; i < kNumberOfValues; ++i) {
          input_promises[i]->set_value(this->global_inputs_[i]);
        }
      }

      std::vector<encrypto::motion::ShareWrapper> results;
      results.reserve(2 * this->values_.size() * this->values_.size());
      for (std::size_t i = 0; i < this->values_.size(); ++i) {
        results.emplace_back(encrypto::motion::algorithm::HammingWeight(input_shares[i]));
      }

      std::vector<encrypto::motion::ShareWrapper> output_results(results.size());
      std::transform(results.begin(), results.end(), output_results.begin(),
                     [](const auto& share) { return share.Out(); });

      this->parties_[party_id]->Run();

      for (std::size_t i = 0; i < this->values_.size(); ++i) {
        auto computed_bvs = output_results[i].As<std::vector<encrypto::motion::BitVector<>>>();
        std::uint8_t computed_value{0};
        for (std::size_t bit_k = 0; bit_k < computed_bvs.size(); ++bit_k) {
          if (computed_bvs[bit_k][0]) computed_value += std::uint8_t(1) << bit_k;
        }
        std::uint8_t expected_value = std::popcount(this->values_[i]);
        EXPECT_EQ(computed_value, expected_value);
      }

      this->parties_[party_id]->Finish();
    }));
  }

  for (auto& f : futures) f.get();
}

}  // namespace