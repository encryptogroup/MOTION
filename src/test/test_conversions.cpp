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

#include <algorithm>
#include <functional>
#include <future>
#include <random>
#include <vector>

#include <fmt/format.h>
#include <gtest/gtest.h>

#include "base/party.h"
#include "multiplication_triple/mt_provider.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "utility/typedefs.h"

#include "test_constants.h"

namespace {
using namespace encrypto::motion;

// number of parties, wires, SIMD values, online-after-setup flag
using ConversionParametersType = std::tuple<std::size_t, std::size_t, std::size_t, bool>;

class ConversionTest : public testing::TestWithParam<ConversionParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parties_, number_of_wires_, number_of_simd_, online_after_setup_) =
        parameters;
  }
  void TearDown() override { number_of_parties_ = number_of_wires_ = number_of_simd_ = 0; }

 protected:
  std::size_t number_of_parties_ = 0, number_of_wires_ = 0, number_of_simd_ = 0;
  bool online_after_setup_ = false;
};

TEST_P(ConversionTest, Y2B) {
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  const std::size_t input_owner = std::rand() % this->number_of_parties_,
                    output_owner = std::rand() % this->number_of_parties_;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(this->number_of_parties_);
  for (auto& bv_v : global_input) {
    bv_v.resize(this->number_of_wires_);
    for (auto& bv : bv_v) {
      bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
    }
  }
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      this->number_of_wires_, encrypto::motion::BitVector<>(this->number_of_simd_, false));

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(this->number_of_parties_, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, &motion_parties, this, input_owner, output_owner,
                            &global_input, &dummy_input]() {
        SharePointer temporary_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          temporary_share =
              motion_parties.at(party_id)->In<kBmr>(global_input.at(input_owner), input_owner);
        } else {
          temporary_share = motion_parties.at(party_id)->In<kBmr>(dummy_input, input_owner);
        }

        encrypto::motion::ShareWrapper share_input(temporary_share);
        EXPECT_EQ(share_input->GetBitLength(), this->number_of_wires_);
        const auto share_conversion{share_input.Convert<MpcProtocol::kBooleanGmw>()};
        auto share_output{share_conversion.Out(output_owner)};

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto i = 0ull; i < this->number_of_wires_; ++i) {
            auto wire_single{std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output->GetWires().at(i))};
            assert(wire_single);
            EXPECT_EQ(wire_single->GetValues(), global_input.at(input_owner).at(i));
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(ConversionTest, B2Y) {
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(0);
  const std::size_t input_owner = std::rand() % this->number_of_parties_,
                    output_owner = std::rand() % this->number_of_parties_;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(this->number_of_parties_);
  for (auto& bv_v : global_input) {
    bv_v.resize(this->number_of_wires_);
    for (auto& bv : bv_v) {
      bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
    }
  }
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      this->number_of_wires_, encrypto::motion::BitVector<>(this->number_of_simd_, false));

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(this->number_of_parties_, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, &motion_parties, this, input_owner, output_owner,
                            &global_input, &dummy_input]() {
        SharePointer temporary_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          temporary_share = motion_parties.at(party_id)->In<kBooleanGmw>(
              global_input.at(input_owner), input_owner);
        } else {
          temporary_share = motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, input_owner);
        }

        encrypto::motion::ShareWrapper share_input(temporary_share);
        EXPECT_EQ(share_input->GetBitLength(), this->number_of_wires_);
        const auto share_conversion{share_input.Convert<MpcProtocol::kBmr>()};
        auto share_output{share_conversion.Out(output_owner)};

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto i = 0ull; i < this->number_of_wires_; ++i) {
            auto wire_single{std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                share_output->GetWires().at(i))};
            assert(wire_single);
            EXPECT_EQ(wire_single->GetPublicValues(), global_input.at(input_owner).at(i));
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

constexpr std::array<std::size_t, 2> kConversionNumberOfParties{2, 3};
constexpr std::array<std::size_t, 3> kConversionNumberOfWires{1, 10, 64};
constexpr std::array<std::size_t, 3> kConversionNumberOfSimd{1, 10, 64};
constexpr std::array<bool, 2> kConversionOnlineAfterSetup{false, true};

INSTANTIATE_TEST_SUITE_P(ConversionTestSuite, ConversionTest,
                         testing::Combine(testing::ValuesIn(kConversionNumberOfParties),
                                          testing::ValuesIn(kConversionNumberOfWires),
                                          testing::ValuesIn(kConversionNumberOfSimd),
                                          testing::ValuesIn(kConversionOnlineAfterSetup)),
                         [](const testing::TestParamInfo<ConversionTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
                           std::string name = fmt::format(
                               "{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                               std::get<1>(info.param), std::get<2>(info.param), mode);
                           return name;
                         });

// number of parties, SIMD values, online-after-setup flag
using ArithmeticConversionParametersType = std::tuple<std::size_t, std::size_t, bool>;

class ArithmeticConversionTest : public testing::TestWithParam<ArithmeticConversionParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parties_, number_of_simd_, online_after_setup_) = parameters;
  }
  void TearDown() override { number_of_parties_ = number_of_simd_ = 0; }

 protected:
  std::size_t number_of_parties_ = 0, number_of_simd_ = 0;
  bool online_after_setup_ = false;
};

template <typename T>
void A2YRun(const std::size_t number_of_parties, const std::size_t number_of_simd,
            const bool online_after_setup) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(0);
  std::mt19937 mersenne_twister(0);
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto r = std::bind(distribution, mersenne_twister);

  const std::size_t input_owner = std::rand() % number_of_parties,
                    output_owner = std::rand() % number_of_parties;
  std::vector<std::vector<T>> global_input(number_of_parties);
  for (auto& v : global_input) {
    v.resize(number_of_simd);
    for (auto& x : v) x = r();
  }
  std::vector<T> dummy_input(number_of_simd, 0);

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(online_after_setup);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back(
          [party_id, &motion_parties, input_owner, output_owner, &global_input, &dummy_input]() {
            SharePointer temporary_share;
            if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              temporary_share = motion_parties.at(party_id)->In<kArithmeticGmw>(
                  global_input.at(input_owner), input_owner);
            } else {
              temporary_share =
                  motion_parties.at(party_id)->In<kArithmeticGmw>(dummy_input, input_owner);
            }

            encrypto::motion::ShareWrapper share_input(temporary_share);
            const auto share_conversion{share_input.Convert<MpcProtocol::kBmr>()};
            const auto share_output{share_conversion.Out(output_owner)};

            motion_parties.at(party_id)->Run();

            std::vector<encrypto::motion::BitVector<>> output_bit_vector;
            if (party_id == output_owner) {
              for (auto i = 0ull; i < share_input->GetBitLength(); ++i) {
                auto wire_single{std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                    share_output->GetWires().at(i))};
                assert(wire_single);
                output_bit_vector.emplace_back(wire_single->GetPublicValues());
              }

              const auto result{encrypto::motion::ToVectorOutput<T>(output_bit_vector)};
              for (auto simd_i = 0ull; simd_i < share_input->GetNumberOfSimdValues(); ++simd_i)
                EXPECT_EQ(result.at(simd_i), global_input.at(input_owner).at(simd_i));
            }
            motion_parties.at(party_id)->Finish();
          });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(ArithmeticConversionTest, A2Y_8_bit) {
  A2YRun<std::uint8_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(ArithmeticConversionTest, A2Y_16_bit) {
  A2YRun<std::uint16_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(ArithmeticConversionTest, A2Y_32_bit) {
  A2YRun<std::uint32_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(ArithmeticConversionTest, A2Y_64_bit) {
  A2YRun<std::uint64_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}

template <typename T>
void A2BRun(const std::size_t number_of_parties, const std::size_t number_of_simd,
            const bool online_after_setup) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(0);
  std::mt19937 mersenne_twister(0);
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto r = std::bind(distribution, mersenne_twister);

  const std::size_t input_owner = std::rand() % number_of_parties,
                    output_owner = std::rand() % number_of_parties;
  std::vector<std::vector<T>> global_input(number_of_parties);
  for (auto& v : global_input) {
    v.resize(number_of_simd);
    for (auto& x : v) x = r();
  }
  std::vector<T> dummy_input(number_of_simd, 0);

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(online_after_setup);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, &motion_parties, input_owner, output_owner, &global_input,
                            &dummy_input]() {
        SharePointer temporary_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          temporary_share = motion_parties.at(party_id)->In<kArithmeticGmw>(
              global_input.at(input_owner), input_owner);
        } else {
          temporary_share =
              motion_parties.at(party_id)->In<kArithmeticGmw>(dummy_input, input_owner);
        }

        encrypto::motion::ShareWrapper share_input(temporary_share);
        const auto share_conversion{share_input.Convert<MpcProtocol::kBooleanGmw>()};
        const auto share_output{share_conversion.Out(output_owner)};

        motion_parties.at(party_id)->Run();

        std::vector<encrypto::motion::BitVector<>> output_bit_vector;
        if (party_id == output_owner) {
          for (auto i = 0ull; i < share_input->GetBitLength(); ++i) {
            auto wire_single{std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output->GetWires().at(i))};
            assert(wire_single);
            output_bit_vector.emplace_back(wire_single->GetValues());
          }

          const auto result{encrypto::motion::ToVectorOutput<T>(output_bit_vector)};
          for (auto simd_i = 0ull; simd_i < share_input->GetNumberOfSimdValues(); ++simd_i)
            EXPECT_EQ(result.at(simd_i), global_input.at(input_owner).at(simd_i));
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(ArithmeticConversionTest, A2B_8_bit) {
  A2BRun<std::uint8_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(ArithmeticConversionTest, A2B_16_bit) {
  A2BRun<std::uint16_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(ArithmeticConversionTest, A2B_32_bit) {
  A2BRun<std::uint32_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(ArithmeticConversionTest, A2B_64_bit) {
  A2BRun<std::uint64_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}

INSTANTIATE_TEST_SUITE_P(
    ArithmeticConversionTestSuite, ArithmeticConversionTest,
    testing::Combine(testing::ValuesIn(kConversionNumberOfParties),
                     testing::ValuesIn(kConversionNumberOfSimd),
                     testing::ValuesIn(kConversionOnlineAfterSetup)),
    [](const testing::TestParamInfo<ArithmeticConversionTest::ParamType>& info) {
      const auto mode = static_cast<bool>(std::get<2>(info.param)) ? "Seq" : "Par";
      std::string name = fmt::format("{}_Parties_{}_SIMD__{}", std::get<0>(info.param),
                                     std::get<1>(info.param), mode);
      return name;
    });

class BooleanConversionTest : public testing::TestWithParam<ArithmeticConversionParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parties_, number_of_simd_, online_after_setup_) = parameters;
  }
  void TearDown() override { number_of_parties_ = number_of_simd_ = 0; }

 protected:
  std::size_t number_of_parties_ = 0, number_of_simd_ = 0;
  bool online_after_setup_ = false;
};

template <typename T>
void B2ARun(const std::size_t number_of_parties, const std::size_t number_of_simd,
            const bool online_after_setup) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto bit_size = sizeof(T) * 8;
  std::srand(0);
  std::mt19937 mersenne_twister(0);
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto r = std::bind(distribution, mersenne_twister);

  const std::size_t input_owner = std::rand() % number_of_parties,
                    output_owner = std::rand() % number_of_parties;
  std::vector<encrypto::motion::BitVector<>> global_input(bit_size);
  for (auto& bv : global_input) {
    bv = encrypto::motion::BitVector<>::SecureRandom(number_of_simd);
  }
  const auto global_input_ashare_inputt{encrypto::motion::ToVectorOutput<T>(global_input)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      bit_size, encrypto::motion::BitVector<>(number_of_simd, false));

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(online_after_setup);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, &motion_parties, input_owner, output_owner, &global_input,
                            &global_input_ashare_inputt, &dummy_input]() {
        SharePointer temporary_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          temporary_share = motion_parties.at(party_id)->In<kBooleanGmw>(global_input, input_owner);
        } else {
          temporary_share = motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, input_owner);
        }

        encrypto::motion::ShareWrapper share_input(temporary_share);
        const auto share_conversion{share_input.Convert<kArithmeticGmw>()};
        const auto share_output{share_conversion.Out(output_owner)};

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          auto wire{std::dynamic_pointer_cast<encrypto::motion::proto::arithmetic_gmw::Wire<T>>(
              share_output->GetWires().at(0))};
          assert(wire);
          auto result = wire->GetValues();

          for (auto simd_i = 0ull; simd_i < share_input->GetNumberOfSimdValues(); ++simd_i)
            EXPECT_EQ(result.at(simd_i), global_input_ashare_inputt.at(simd_i));
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(BooleanConversionTest, B2A_8_bit) {
  B2ARun<std::uint8_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(BooleanConversionTest, B2A_16_bit) {
  B2ARun<std::uint16_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(BooleanConversionTest, B2A_32_bit) {
  B2ARun<std::uint32_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(BooleanConversionTest, B2A_64_bit) {
  B2ARun<std::uint64_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}

INSTANTIATE_TEST_SUITE_P(BooleanConversionTestSuite, BooleanConversionTest,
                         testing::Combine(testing::ValuesIn(kConversionNumberOfParties),
                                          testing::ValuesIn(kConversionNumberOfSimd),
                                          testing::ValuesIn(kConversionOnlineAfterSetup)),
                         [](const testing::TestParamInfo<BooleanConversionTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<2>(info.param)) ? "Seq" : "Par";
                           std::string name =
                               fmt::format("{}_Parties_{}_SIMD__{}", std::get<0>(info.param),
                                           std::get<1>(info.param), mode);
                           return name;
                         });

class YaoConversionTest : public testing::TestWithParam<ArithmeticConversionParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parties_, number_of_simd_, online_after_setup_) = parameters;
  }
  void TearDown() override { number_of_parties_ = number_of_simd_ = 0; }

 protected:
  std::size_t number_of_parties_ = 0, number_of_simd_ = 0;
  bool online_after_setup_ = false;
};

template <typename T>
void Y2ARun(const std::size_t number_of_parties, const std::size_t number_of_simd,
            const bool online_after_setup) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto bit_size = sizeof(T) * 8;
  std::srand(0);
  std::mt19937 mersenne_twister(0);
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto r = std::bind(distribution, mersenne_twister);

  const std::size_t input_owner = std::rand() % number_of_parties,
                    output_owner = std::rand() % number_of_parties;
  std::vector<encrypto::motion::BitVector<>> global_input(bit_size);
  for (auto& bv : global_input) {
    bv = encrypto::motion::BitVector<>::SecureRandom(number_of_simd);
  }
  const auto global_input_ashare_inputt{encrypto::motion::ToVectorOutput<T>(global_input)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      bit_size, encrypto::motion::BitVector<>(number_of_simd, false));

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(online_after_setup);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, &motion_parties, input_owner, output_owner, &global_input,
                            &global_input_ashare_inputt, &dummy_input]() {
        SharePointer temporary_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          temporary_share = motion_parties.at(party_id)->In<kBmr>(global_input, input_owner);
        } else {
          temporary_share = motion_parties.at(party_id)->In<kBmr>(dummy_input, input_owner);
        }

        encrypto::motion::ShareWrapper share_input(temporary_share);
        const auto share_conversion{share_input.Convert<kArithmeticGmw>()};
        const auto share_output{share_conversion.Out(output_owner)};

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          auto wire{std::dynamic_pointer_cast<encrypto::motion::proto::arithmetic_gmw::Wire<T>>(
              share_output->GetWires().at(0))};
          assert(wire);
          auto result = wire->GetValues();

          for (auto simd_i = 0ull; simd_i < share_input->GetNumberOfSimdValues(); ++simd_i)
            EXPECT_EQ(result.at(simd_i), global_input_ashare_inputt.at(simd_i));
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(YaoConversionTest, Y2A_8_bit) {
  Y2ARun<std::uint8_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(YaoConversionTest, Y2A_16_bit) {
  Y2ARun<std::uint16_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(YaoConversionTest, Y2A_32_bit) {
  Y2ARun<std::uint32_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}
TEST_P(YaoConversionTest, Y2A_64_bit) {
  Y2ARun<std::uint64_t>(this->number_of_parties_, this->number_of_simd_, this->online_after_setup_);
}

INSTANTIATE_TEST_SUITE_P(YaoConversionTestSuite, YaoConversionTest,
                         testing::Combine(testing::ValuesIn(kConversionNumberOfParties),
                                          testing::ValuesIn(kConversionNumberOfSimd),
                                          testing::ValuesIn(kConversionOnlineAfterSetup)),
                         [](const testing::TestParamInfo<YaoConversionTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<2>(info.param)) ? "Seq" : "Par";
                           std::string name =
                               fmt::format("{}_Parties_{}_SIMD__{}", std::get<0>(info.param),
                                           std::get<1>(info.param), mode);
                           return name;
                         });

}  // namespace
