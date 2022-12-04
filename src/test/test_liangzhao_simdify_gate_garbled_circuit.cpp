// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko
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

#include <future>
#include <random>

#include <gtest/gtest.h>

#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_constants.h"

namespace {

// number of parties, wires, SIMD values, online-after-setup flag
using ParametersType = std::tuple<std::size_t, std::size_t, std::size_t, bool>;

class SimdifyTest : public testing::TestWithParam<ParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parties_, number_of_wires_, number_of_simd_, online_after_setup_) =
        parameters;

    std::uniform_int_distribution<std::size_t> number_of_positions(1, 1000);
    std::uniform_int_distribution<std::size_t> dist(0, this->number_of_simd_ - 1);

    std::mt19937_64 mersenne_twister(this->number_of_parties_ + this->number_of_wires_ +
                                     this->number_of_simd_ + this->online_after_setup_);

    subset_size_ = dist(mersenne_twister);

    // Generate random inputs.
    plaintext_boolean_input_.resize(this->number_of_wires_);
    for (std::size_t i = 0; i < plaintext_boolean_input_.size(); ++i) {
      this->plaintext_boolean_input_[i] =
          encrypto::motion::BitVector<>::RandomSeeded(this->number_of_simd_, i);
    }
    std::get<std::vector<std::uint8_t>>(this->plaintext_arithmetic_input_) =
        RandomVectorOfUints<std::uint8_t>(mersenne_twister, this->number_of_simd_);
    std::get<std::vector<std::uint16_t>>(this->plaintext_arithmetic_input_) =
        RandomVectorOfUints<std::uint16_t>(mersenne_twister, this->number_of_simd_);
    std::get<std::vector<std::uint32_t>>(this->plaintext_arithmetic_input_) =
        RandomVectorOfUints<std::uint32_t>(mersenne_twister, this->number_of_simd_);
    std::get<std::vector<std::uint64_t>>(this->plaintext_arithmetic_input_) =
        RandomVectorOfUints<std::uint64_t>(mersenne_twister, this->number_of_simd_);

    this->motion_parties_ = std::vector<encrypto::motion::PartyPointer>(std::move(
        encrypto::motion::MakeLocallyConnectedParties(this->number_of_parties_, kPortOffset)));
    for (auto& party : this->motion_parties_) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
  }
  void TearDown() override { number_of_parties_ = number_of_wires_ = number_of_simd_ = 0; }

  void CheckCorrectness(std::vector<encrypto::motion::BitVector<>> simdify_circuit_result) {
    for (std::size_t wire_i = 0; wire_i < number_of_wires_; ++wire_i) {
      auto expected_result{this->plaintext_boolean_input_[wire_i].Subset(0, 1)};
      expected_result.Append(this->plaintext_boolean_input_[wire_i]);
      expected_result.Append(this->plaintext_boolean_input_[wire_i].Subset(0, 1));
      expected_result.Append(this->plaintext_boolean_input_[wire_i].Subset(0, 1));
      expected_result.Append(this->plaintext_boolean_input_[wire_i].Subset(0, 1));
      expected_result.Append(this->plaintext_boolean_input_[wire_i].Subset(0, 1));
      EXPECT_EQ(simdify_circuit_result[wire_i], expected_result);
    }
  }

  template <typename T>
  void CheckCorrectness(std::vector<T> simdify_circuit_result) {
    const std::vector<T>& plaintext{std::get<std::vector<T>>(this->plaintext_arithmetic_input_)};
    std::vector<T> expected_result;
    expected_result.emplace_back(plaintext[0]);
    expected_result.insert(expected_result.end(), plaintext.begin(), plaintext.end());
    expected_result.emplace_back(plaintext[0]);
    expected_result.emplace_back(plaintext[0]);
    expected_result.emplace_back(plaintext[0]);
    expected_result.emplace_back(plaintext[0]);
    EXPECT_EQ(simdify_circuit_result, expected_result);
  }

 protected:
  std::size_t number_of_parties_ = 0, number_of_wires_ = 0, number_of_simd_ = 0, input_owner_ = 0;
  bool online_after_setup_ = false;
  std::vector<encrypto::motion::BitVector<>> plaintext_boolean_input_;
  std::tuple<std::vector<std::uint8_t>, std::vector<std::uint16_t>, std::vector<std::uint32_t>,
             std::vector<std::uint64_t>>
      plaintext_arithmetic_input_;
  std::vector<encrypto::motion::PartyPointer> motion_parties_;
  std::size_t subset_size_;

  template <typename T>
  static std::vector<T> RandomVectorOfUints(std::mt19937_64& mersenne_twister, std::size_t size) {
    std::uniform_int_distribution<T> dist;
    std::vector<T> result(size);
    for (auto& value : result) value = dist(mersenne_twister);
    return result;
  }
};

class BooleanSimdifyTest : public SimdifyTest {};

TEST_P(BooleanSimdifyTest, GarbledCircuit) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        encrypto::motion::ShareWrapper share_input{
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
                this->plaintext_boolean_input_, this->input_owner_)};

        std::vector input_to_simdify{share_input.Subset({0}), share_input, share_input.Subset({0}),
                                     share_input.Subset({0, 0, 0})};
        encrypto::motion::ShareWrapper share_simdified =
            encrypto::motion::ShareWrapper::Simdify(input_to_simdify);
        encrypto::motion::ShareWrapper share_output{share_simdified.Out()};

        this->motion_parties_.at(party_id)->Run();

        // input owner checks the correctness
        if (party_id == this->input_owner_) {
          this->CheckCorrectness(share_output.As<std::vector<encrypto::motion::BitVector<>>>());
        }
        std::cout << "party finish" << std::endl;
        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

// test for garbled circuit simdify gate
// constexpr std::array<std::size_t, 1> kBooleanNumberOfParties{2};
// constexpr std::array<std::size_t, 2> kBooleanNumberOfWires{1, 64};
// constexpr std::array<std::size_t, 3> kBooleanNumberOfSimd{1, 64, 100};
// constexpr std::array<bool, 2> kBooleanOnlineAfterSetup{false, true};

// only for debugging
constexpr std::array<std::size_t, 1> kBooleanNumberOfParties{2};
constexpr std::array<std::size_t, 1> kBooleanNumberOfWires{1};
constexpr std::array<std::size_t, 1> kBooleanNumberOfSimd{1};
constexpr std::array<bool, 1> kBooleanOnlineAfterSetup{false};

INSTANTIATE_TEST_SUITE_P(DataManagementTestSuite, BooleanSimdifyTest,
                         testing::Combine(testing::ValuesIn(kBooleanNumberOfParties),
                                          testing::ValuesIn(kBooleanNumberOfWires),
                                          testing::ValuesIn(kBooleanNumberOfSimd),
                                          testing::ValuesIn(kBooleanOnlineAfterSetup)),
                         [](const testing::TestParamInfo<SimdifyTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
                           std::string name = fmt::format(
                               "{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                               std::get<1>(info.param), std::get<2>(info.param), mode);
                           return name;
                         });

}  // namespace
