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

class SubsetTest : public testing::TestWithParam<ParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parties_, number_of_wires_, number_of_simd_, online_after_setup_) =
        parameters;

    std::uniform_int_distribution<std::size_t> number_of_positions(1, 1000);
    std::uniform_int_distribution<std::size_t> dist(0, this->number_of_simd_ - 1);

    std::mt19937_64 mersenne_twister(this->number_of_parties_ + this->number_of_wires_ +
                                     this->number_of_simd_ + this->online_after_setup_);
    this->positions_ = std::vector<std::size_t>(number_of_positions(mersenne_twister));
    for (std::size_t& i : this->positions_) {
      i = dist(mersenne_twister);
    }

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

  void CheckCorrectness(const std::vector<encrypto::motion::BitVector<>>& subset_circuit_result) {
    std::vector<encrypto::motion::BitVector<>> subset_expected(
        this->number_of_wires_, encrypto::motion::BitVector<>(this->positions_.size()));
    for (std::size_t i = 0; i < subset_expected.size(); ++i) {
      for (std::size_t j = 0; j < this->positions_.size(); ++j) {
        subset_expected[i].Set(this->plaintext_boolean_input_[i][this->positions_[j]], j);
      }
    }
    EXPECT_EQ(subset_circuit_result, subset_expected);
  }

  template <typename T>
  void CheckCorrectness(std::vector<T> subset_circuit_result) {
    std::vector<T> subset_expected(this->positions_.size());
    for (std::size_t i = 0; i < this->positions_.size(); ++i) {
      subset_expected[i] =
          std::get<std::vector<T>>(this->plaintext_arithmetic_input_)[this->positions_[i]];
    }
    EXPECT_EQ(subset_circuit_result, subset_expected);
  }

 protected:
  std::size_t number_of_parties_ = 0, number_of_wires_ = 0, number_of_simd_ = 0, input_owner_ = 0;
  bool online_after_setup_ = false;
  std::vector<std::size_t> positions_;
  std::vector<encrypto::motion::BitVector<>> plaintext_boolean_input_;
  std::tuple<std::vector<std::uint8_t>, std::vector<std::uint16_t>, std::vector<std::uint32_t>,
             std::vector<std::uint64_t>>
      plaintext_arithmetic_input_;
  std::vector<encrypto::motion::PartyPointer> motion_parties_;

  template <typename T>
  static std::vector<T> RandomVectorOfUints(std::mt19937_64& mersenne_twister, std::size_t size) {
    std::uniform_int_distribution<T> dist;
    std::vector<T> result(size);
    for (auto& value : result) value = dist(mersenne_twister);
    return result;
  }
};

class BooleanSubsetTest : public SubsetTest {};
class ArithmeticSubsetTest : public SubsetTest {};

TEST_P(BooleanSubsetTest, Bmr) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        encrypto::motion::ShareWrapper share_input{
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kBmr>(
                this->plaintext_boolean_input_, this->input_owner_)};

        auto share_subset = share_input.Subset(this->positions_);
        auto share_output = share_subset.Out();

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

// "OR" the output with itself after taking the subset to ensure that the secret and public keys are
// also on the right places.
TEST_P(BooleanSubsetTest, BmrKeyConsistency) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        encrypto::motion::ShareWrapper share_input{
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kBmr>(
                this->plaintext_boolean_input_, this->input_owner_)};

        auto share_subset = share_input.Subset(this->positions_);
        auto share_output = (share_subset | share_subset).Out();

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

TEST_P(BooleanSubsetTest, BooleanGmw) {
  try {
    std::vector<std::future<void>> futures;
    for (std::size_t party_id = 0; party_id < this->motion_parties_.size(); ++party_id) {
      futures.push_back(std::async(std::launch::async, [party_id, this]() {
        encrypto::motion::ShareWrapper share_input{
            this->motion_parties_.at(party_id)->In<encrypto::motion::MpcProtocol::kBooleanGmw>(
                this->plaintext_boolean_input_, this->input_owner_)};

        auto share_subset = share_input.Subset(this->positions_);
        auto share_output = share_subset.Out();

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

TEST_P(ArithmeticSubsetTest, ArithmeticGmw) {
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

        std::array<encrypto::motion::ShareWrapper, 4> share_subset;
        std::transform(share_input.begin(), share_input.end(), share_subset.begin(),
                       [this](encrypto::motion::ShareWrapper& share_wrapper) {
                         return share_wrapper.Subset(this->positions_);
                       });
        std::array<encrypto::motion::ShareWrapper, 4> share_output;
        std::transform(share_subset.begin(), share_subset.end(), share_output.begin(),
                       [this](const encrypto::motion::ShareWrapper& share_wrapper) {
                         return share_wrapper.Out();
                       });

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
TEST_P(ArithmeticSubsetTest, ArithmeticConstant) {
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

        std::array<encrypto::motion::ShareWrapper, 4> constant_share_subset;
        std::transform(constant_share_input.begin(), constant_share_input.end(),
                       constant_share_subset.begin(),
                       [this](encrypto::motion::ShareWrapper& share_wrapper) {
                         return share_wrapper.Subset(this->positions_);
                       });

        this->motion_parties_.at(party_id)->Run();

        this->CheckCorrectness(constant_share_subset[0].As<std::vector<uint8_t>>());
        this->CheckCorrectness(constant_share_subset[1].As<std::vector<uint16_t>>());
        this->CheckCorrectness(constant_share_subset[2].As<std::vector<uint32_t>>());
        this->CheckCorrectness(constant_share_subset[3].As<std::vector<uint64_t>>());

        this->motion_parties_.at(party_id)->Finish();
      }));
    }
    for (auto& f : futures) f.get();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(ArithmeticSubsetTest, SecureUnsignedInteger) {
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

        std::array<encrypto::motion::SecureUnsignedInteger, 4> share_subset;
        std::transform(share_input.begin(), share_input.end(), share_subset.begin(),
                       [this](encrypto::motion::SecureUnsignedInteger& share_wrapper) {
                         return share_wrapper.Subset(this->positions_);
                       });
        std::array<encrypto::motion::SecureUnsignedInteger, 4> share_output;
        std::transform(share_subset.begin(), share_subset.end(), share_output.begin(),
                       [this](const encrypto::motion::SecureUnsignedInteger& share_wrapper) {
                         return share_wrapper.Out();
                       });

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

INSTANTIATE_TEST_SUITE_P(DataManagementTestSuite, BooleanSubsetTest,
                         testing::Combine(testing::ValuesIn(kBooleanNumberOfParties),
                                          testing::ValuesIn(kBooleanNumberOfWires),
                                          testing::ValuesIn(kBooleanNumberOfSimd),
                                          testing::ValuesIn(kBooleanOnlineAfterSetup)),
                         [](const testing::TestParamInfo<SubsetTest::ParamType>& info) {
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

INSTANTIATE_TEST_SUITE_P(DataManagementTestSuite, ArithmeticSubsetTest,
                         testing::Combine(testing::ValuesIn(kArithmeticNumberOfParties),
                                          testing::ValuesIn(kArithmeticNumberOfWires),
                                          testing::ValuesIn(kArithmeticNumberOfSimd),
                                          testing::ValuesIn(kArithmeticOnlineAfterSetup)),
                         [](const testing::TestParamInfo<SubsetTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
                           std::string name = fmt::format(
                               "{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                               std::get<1>(info.param), std::get<2>(info.param), mode);
                           return name;
                         });
}  // namespace
