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
class ArithmeticSimdifyTest : public SimdifyTest {};

TEST_P(BooleanSimdifyTest, Bmr) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        encrypto::motion::ShareWrapper share_input{
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kBmr>(
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
        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

// "OR" the output with itself after takinhe subset to ensure that the secret and public keys are
// also on the right places.
TEST_P(BooleanSimdifyTest, BmrKeyConsistency) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        encrypto::motion::ShareWrapper share_input{
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kBmr>(
                this->plaintext_boolean_input_, this->input_owner_)};

        std::vector input_to_simdify{share_input.Subset({0}), share_input, share_input.Subset({0}),
                                     share_input.Subset({0, 0, 0})};
        encrypto::motion::ShareWrapper share_simdified =
            encrypto::motion::ShareWrapper::Simdify(input_to_simdify);
        encrypto::motion::ShareWrapper share_output{(share_simdified | share_simdified).Out()};

        this->motion_parties_.at(party_id)->Run();

        // input owner checks the correctness
        if (party_id == this->input_owner_) {
          this->CheckCorrectness(share_output.As<std::vector<encrypto::motion::BitVector<>>>());
        }
        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(BooleanSimdifyTest, BooleanGmw) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        encrypto::motion::ShareWrapper share_input{
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kBooleanGmw>(
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
        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(ArithmeticSimdifyTest, ArithmeticGmw) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        std::array<encrypto::motion::ShareWrapper, 4> share_input;
        share_input[0] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint8_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);
        share_input[1] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint16_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);
        share_input[2] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint32_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);
        share_input[3] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint64_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);

        std::array<std::vector<encrypto::motion::ShareWrapper>, 4> input_to_simdify;
        std::transform(share_input.begin(), share_input.end(), input_to_simdify.begin(),
                       [this](encrypto::motion::ShareWrapper& share_wrapper) {
                         return std::vector{share_wrapper.Subset({0}), share_wrapper,
                                            share_wrapper.Subset({0}),
                                            share_wrapper.Subset({0, 0, 0})};
                       });

        std::array<encrypto::motion::ShareWrapper, 4> share_simdified;
        std::transform(input_to_simdify.begin(), input_to_simdify.end(), share_simdified.begin(),
                       [this](std::vector<encrypto::motion::ShareWrapper>& input) {
                         return encrypto::motion::ShareWrapper::Simdify(input);
                       });
        std::array<encrypto::motion::ShareWrapper, 4> share_output;
        std::transform(
            share_simdified.begin(), share_simdified.end(), share_output.begin(),
            [this](encrypto::motion::ShareWrapper share_wrapper) { return share_wrapper.Out(); });

        this->motion_parties_.at(party_id)->Run();

        // input owner checks the correctness
        if (party_id == this->input_owner_) {
          this->CheckCorrectness(share_output[0].As<std::vector<uint8_t>>());
          this->CheckCorrectness(share_output[1].As<std::vector<uint16_t>>());
          this->CheckCorrectness(share_output[2].As<std::vector<uint32_t>>());
          this->CheckCorrectness(share_output[3].As<std::vector<uint64_t>>());
        }
        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

// Add arithmetic GMW shares to the result to be able to output a value.
TEST_P(ArithmeticSimdifyTest, ArithmeticConstant) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        std::array<encrypto::motion::ShareWrapper, 4> constant_share_input;
        constant_share_input[0] =
            this->motion_parties_.at(party_id)
                ->In<encrypto::motion::MpcProtocol::kArithmeticConstant>(
                    std::get<std::vector<uint8_t>>(this->plaintext_arithmetic_input_));
        constant_share_input[1] =
            this->motion_parties_.at(party_id)
                ->In<encrypto::motion::MpcProtocol::kArithmeticConstant>(
                    std::get<std::vector<uint16_t>>(this->plaintext_arithmetic_input_));
        constant_share_input[2] =
            this->motion_parties_.at(party_id)
                ->In<encrypto::motion::MpcProtocol::kArithmeticConstant>(
                    std::get<std::vector<uint32_t>>(this->plaintext_arithmetic_input_));
        constant_share_input[3] =
            this->motion_parties_.at(party_id)
                ->In<encrypto::motion::MpcProtocol::kArithmeticConstant>(
                    std::get<std::vector<uint64_t>>(this->plaintext_arithmetic_input_));

        std::array<std::vector<encrypto::motion::ShareWrapper>, 4> input_to_simdify;
        std::transform(
            constant_share_input.begin(), constant_share_input.end(), input_to_simdify.begin(),
            [this](encrypto::motion::ShareWrapper& share_wrapper) {
              return std::vector{share_wrapper.Subset({0}), share_wrapper,
                                 share_wrapper.Subset({0}), share_wrapper.Subset({0, 0, 0})};
            });

        std::array<encrypto::motion::ShareWrapper, 4> share_simdified;
        std::transform(input_to_simdify.begin(), input_to_simdify.end(), share_simdified.begin(),
                       [this](std::vector<encrypto::motion::ShareWrapper>& input) {
                         return encrypto::motion::ShareWrapper::Simdify(input);
                       });

        this->motion_parties_.at(party_id)->Run();

        this->CheckCorrectness(share_simdified[0].As<std::vector<uint8_t>>());
        this->CheckCorrectness(share_simdified[1].As<std::vector<uint16_t>>());
        this->CheckCorrectness(share_simdified[2].As<std::vector<uint32_t>>());
        this->CheckCorrectness(share_simdified[3].As<std::vector<uint64_t>>());

        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(ArithmeticSimdifyTest, SecureUnsignedInteger) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        std::array<encrypto::motion::SecureUnsignedInteger, 4> share_input;
        share_input[0] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint8_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);
        share_input[1] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint16_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);
        share_input[2] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint32_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);
        share_input[3] =
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(
                std::get<std::vector<uint64_t>>(this->plaintext_arithmetic_input_),
                this->input_owner_);

        std::array<std::vector<encrypto::motion::SecureUnsignedInteger>, 4> input_to_simdify;
        std::transform(share_input.begin(), share_input.end(), input_to_simdify.begin(),
                       [this](encrypto::motion::SecureUnsignedInteger& secure_uint) {
                         return std::vector{secure_uint.Subset({0}), secure_uint,
                                            secure_uint.Subset({0}),
                                            secure_uint.Subset({0, 0, 0})};
                       });

        std::array<encrypto::motion::SecureUnsignedInteger, 4> share_simdified;
        std::transform(input_to_simdify.begin(), input_to_simdify.end(), share_simdified.begin(),
                       [this](std::vector<encrypto::motion::SecureUnsignedInteger>& input) {
                         return encrypto::motion::SecureUnsignedInteger::Simdify(input);
                       });
        std::array<encrypto::motion::SecureUnsignedInteger, 4> share_output;
        std::transform(
            share_simdified.begin(), share_simdified.end(), share_output.begin(),
            [this](encrypto::motion::SecureUnsignedInteger secure_uint) { return secure_uint.Out(); });

        this->motion_parties_.at(party_id)->Run();

        // input owner checks the correctness
        if (party_id == this->input_owner_) {
          this->CheckCorrectness(share_output[0].As<std::vector<uint8_t>>());
          this->CheckCorrectness(share_output[1].As<std::vector<uint16_t>>());
          this->CheckCorrectness(share_output[2].As<std::vector<uint32_t>>());
          this->CheckCorrectness(share_output[3].As<std::vector<uint64_t>>());
        }
        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

constexpr std::array<std::size_t, 2> kBooleanNumberOfParties{2, 3};
constexpr std::array<std::size_t, 2> kBooleanNumberOfWires{1, 64};
constexpr std::array<std::size_t, 3> kBooleanNumberOfSimd{1, 64, 100};
constexpr std::array<bool, 2> kBooleanOnlineAfterSetup{false, true};

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

constexpr std::array<std::size_t, 2> kArithmeticNumberOfParties{2, 3};
constexpr std::array<std::size_t, 3> kArithmeticNumberOfSimd{1, 64, 100};
constexpr std::array<std::size_t, 1> kArithmeticNumberOfWires{1};
constexpr std::array<bool, 2> kArithmeticOnlineAfterSetup{false, true};

INSTANTIATE_TEST_SUITE_P(DataManagementTestSuite, ArithmeticSimdifyTest,
                         testing::Combine(testing::ValuesIn(kArithmeticNumberOfParties),
                                          testing::ValuesIn(kArithmeticNumberOfWires),
                                          testing::ValuesIn(kArithmeticNumberOfSimd),
                                          testing::ValuesIn(kArithmeticOnlineAfterSetup)),
                         [](const testing::TestParamInfo<SimdifyTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
                           std::string name = fmt::format(
                               "{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                               std::get<1>(info.param), std::get<2>(info.param), mode);
                           return name;
                         });
}  // namespace
