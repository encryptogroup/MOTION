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
using ParametersType = std::tuple<std::size_t, std::size_t, std::size_t, bool>;

class BmrTest : public testing::TestWithParam<ParametersType> {
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

TEST_P(BmrTest, InputOutput) {
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
        SharePointer tmp_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          tmp_share =
              motion_parties.at(party_id)->In<kBmr>(global_input.at(input_owner), input_owner);
        } else {
          tmp_share = motion_parties.at(party_id)->In<kBmr>(dummy_input, input_owner);
        }

        encrypto::motion::ShareWrapper share_input(tmp_share);
        EXPECT_EQ(share_input->GetBitLength(), this->number_of_wires_);
        auto share_output = share_input.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto i = 0ull; i < number_of_wires_; ++i) {
            auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                share_output->GetWires().at(i));
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

TEST_P(BmrTest, Inv) {
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  const std::size_t input_owner = std::rand() % this->number_of_parties_,
                    output_owner = std::rand() % this->number_of_parties_;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(this->number_of_parties_);
  for (auto& bv_v : global_input) {
    bv_v.resize(this->number_of_wires_);
    for (auto& bv : bv_v) bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
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
        SharePointer tmp_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          tmp_share =
              motion_parties.at(party_id)->In<kBmr>(global_input.at(input_owner), input_owner);
        } else {
          tmp_share = motion_parties.at(party_id)->In<kBmr>(dummy_input, input_owner);
        }

        encrypto::motion::ShareWrapper share_input(tmp_share);
        share_input = ~share_input;
        auto share_output = share_input.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto i = 0ull; i < number_of_wires_; ++i) {
            auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                share_output->GetWires().at(i));
            assert(wire_single);
            EXPECT_EQ(wire_single->GetPublicValues(), ~global_input.at(input_owner).at(i));
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

TEST_P(BmrTest, Xor) {
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  const std::size_t output_owner = std::rand() % this->number_of_parties_;
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
      threads.emplace_back(
          [party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
            std::vector<encrypto::motion::ShareWrapper> share_input;

            for (auto j = 0ull; j < this->number_of_parties_; ++j) {
              if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
                share_input.push_back(motion_parties.at(party_id)->In<kBmr>(global_input.at(j), j));
              } else {
                share_input.push_back(motion_parties.at(party_id)->In<kBmr>(dummy_input, j));
              }
            }

            auto share_xor = share_input.at(0) ^ share_input.at(1);

            for (auto j = 2ull; j < this->number_of_parties_; ++j) {
              share_xor = share_xor ^ share_input.at(j);
            }

            auto share_output = share_xor.Out(output_owner);

            motion_parties.at(party_id)->Run();

            if (party_id == output_owner) {
              for (auto j = 0ull; j < this->number_of_wires_; ++j) {
                auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                    share_output->GetWires().at(j));
                assert(wire_single);

                std::vector<encrypto::motion::BitVector<>> global_input_single;
                for (auto k = 0ull; k < this->number_of_parties_; ++k) {
                  global_input_single.push_back(global_input.at(k).at(j));
                }

                EXPECT_EQ(wire_single->GetPublicValues(),
                          encrypto::motion::BitVector<>::XorBitVectors(global_input_single));
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

constexpr std::array<std::size_t, 2> kBmrNumberOfParties{2, 5};
constexpr std::array<std::size_t, 2> kBmrNumberOfWires{1, 64};
constexpr std::array<std::size_t, 2> kBmrNumberOfSimd{1, 64};
constexpr std::array<bool, 2> kBmrOnlineAfterSetup{false, true};

INSTANTIATE_TEST_SUITE_P(
    BmrTestSuite, BmrTest,
    testing::Combine(testing::ValuesIn(kBmrNumberOfParties), testing::ValuesIn(kBmrNumberOfWires),
                     testing::ValuesIn(kBmrNumberOfSimd), testing::ValuesIn(kBmrOnlineAfterSetup)),
    [](const testing::TestParamInfo<BmrTest::ParamType>& info) {
      const auto mode = static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
      std::string name = fmt::format("{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                                     std::get<1>(info.param), std::get<2>(info.param), mode);
      return name;
    });

class BmrHeavyTest : public testing::TestWithParam<ParametersType> {
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

TEST_P(BmrHeavyTest, And) {
  EXPECT_NE(number_of_parties_, 0);
  EXPECT_NE(number_of_wires_, 0);
  EXPECT_NE(number_of_simd_, 0);

  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  const std::size_t output_owner = std::rand() % number_of_parties_;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(number_of_parties_);
  for (auto& bv_v : global_input) {
    bv_v.resize(number_of_wires_);
    for (auto& bv : bv_v) {
      bv = encrypto::motion::BitVector<>::SecureRandom(number_of_simd_);
    }
  }
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      number_of_wires_, encrypto::motion::BitVector<>(number_of_simd_, false));

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties_, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back(
          [party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
            std::vector<encrypto::motion::ShareWrapper> share_input;

            for (auto j = 0ull; j < this->number_of_parties_; ++j) {
              if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
                share_input.push_back(motion_parties.at(party_id)->In<kBmr>(global_input.at(j), j));
              } else {
                share_input.push_back(motion_parties.at(party_id)->In<kBmr>(dummy_input, j));
              }
            }

            auto share_and = share_input.at(0) & share_input.at(1);

            for (auto j = 2ull; j < this->number_of_parties_; ++j) {
              share_and = share_and & share_input.at(j);
            }

            auto share_output = share_and.Out(output_owner);

            motion_parties.at(party_id)->Run();

            if (party_id == output_owner) {
              for (auto j = 0ull; j < share_output->GetWires().size(); ++j) {
                auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                    share_output->GetWires().at(j));
                assert(wire_single);

                std::vector<encrypto::motion::BitVector<>> global_input_single;
                for (auto k = 0ull; k < this->number_of_parties_; ++k) {
                  global_input_single.push_back(global_input.at(k).at(j));
                }

                EXPECT_EQ(wire_single->GetPublicValues(),
                          encrypto::motion::BitVector<>::AndBitVectors(global_input_single));
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

TEST_P(BmrHeavyTest, Or) {
  EXPECT_NE(number_of_parties_, 0);
  EXPECT_NE(number_of_wires_, 0);
  EXPECT_NE(number_of_simd_, 0);

  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  const std::size_t output_owner = std::rand() % number_of_parties_;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(number_of_parties_);
  for (auto& bv_v : global_input) {
    bv_v.resize(number_of_wires_);
    for (auto& bv : bv_v) {
      bv = encrypto::motion::BitVector<>::SecureRandom(number_of_simd_);
    }
  }
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      number_of_wires_, encrypto::motion::BitVector<>(number_of_simd_, false));

  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties_, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back(
          [party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
            std::vector<encrypto::motion::ShareWrapper> share_input;

            for (auto j = 0ull; j < this->number_of_parties_; ++j) {
              if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
                share_input.push_back(motion_parties.at(party_id)->In<kBmr>(global_input.at(j), j));
              } else {
                share_input.push_back(motion_parties.at(party_id)->In<kBmr>(dummy_input, j));
              }
            }

            auto share_or = share_input.at(0) | share_input.at(1);

            for (auto j = 2ull; j < this->number_of_parties_; ++j) {
              share_or = share_or | share_input.at(j);
            }

            auto share_output = share_or.Out(output_owner);

            motion_parties.at(party_id)->Run();

            if (party_id == output_owner) {
              for (auto j = 0ull; j < share_output->GetWires().size(); ++j) {
                auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                    share_output->GetWires().at(j));
                assert(wire_single);

                std::vector<encrypto::motion::BitVector<>> global_input_single;
                for (auto k = 0ull; k < this->number_of_parties_; ++k) {
                  global_input_single.push_back(global_input.at(k).at(j));
                }

                EXPECT_EQ(wire_single->GetPublicValues(),
                          encrypto::motion::BitVector<>::OrBitVectors(global_input_single));
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

TEST_P(BmrHeavyTest, Mux) {
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  const std::size_t input1_owner = std::rand() % this->number_of_parties_,
                    input2_owner = std::rand() % this->number_of_parties_,
                    selection_bit_owner = std::rand() % this->number_of_parties_,
                    output_owner = std::rand() % this->number_of_parties_;
  std::vector<encrypto::motion::BitVector<>> global_input1(this->number_of_wires_),
      global_input2(this->number_of_wires_);
  for (auto& bv : global_input1) bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
  for (auto& bv : global_input2) bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
  encrypto::motion::BitVector<> bit_vector_selection =
      encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);

  std::vector<encrypto::motion::BitVector<>> dummy_input(
      this->number_of_wires_, encrypto::motion::BitVector<>(this->number_of_simd_, false));
  encrypto::motion::BitVector<> dummy_selection(this->number_of_simd_);

  std::vector<PartyPointer> motion_parties(
      std::move(MakeLocallyConnectedParties(this->number_of_parties_, kPortOffset)));
  for (auto& parties : motion_parties) {
    parties->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    parties->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, this, input1_owner, input2_owner,
                          selection_bit_owner, output_owner, &global_input1, &global_input2,
                          &bit_vector_selection, &dummy_input, &dummy_selection]() {
      const auto my_id = motion_parties.at(party_id)->GetConfiguration()->GetMyId();
      SharePointer share_input1;
      if (input1_owner == my_id) {
        share_input1 = motion_parties.at(party_id)->In<kBmr>(global_input1, input1_owner);
      } else {
        share_input1 = motion_parties.at(party_id)->In<kBmr>(dummy_input, input1_owner);
      }

      SharePointer share_input2;
      if (input2_owner == my_id) {
        share_input2 = motion_parties.at(party_id)->In<kBmr>(global_input2, input2_owner);
      } else {
        share_input2 = motion_parties.at(party_id)->In<kBmr>(dummy_input, input2_owner);
      }

      SharePointer share_selection;
      if (selection_bit_owner == my_id) {
        share_selection =
            motion_parties.at(party_id)->In<kBmr>(bit_vector_selection, selection_bit_owner);
      } else {
        share_selection =
            motion_parties.at(party_id)->In<kBmr>(dummy_selection, selection_bit_owner);
      }

      encrypto::motion::ShareWrapper sw_in1(share_input1), sw_in2(share_input2),
          sw_sel(share_selection);

      // sw_sel ? sw_in_1 : sw_in_2
      auto sw_res = sw_sel.Mux(sw_in1, sw_in2);

      auto sw_out = sw_res.Out(output_owner);

      motion_parties.at(party_id)->Run();

      if (party_id == output_owner) {
        for (auto i = 0ull; i < number_of_wires_; ++i) {
          auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
              sw_out->GetWires().at(i));
          assert(wire_single);
          for (auto j = 0ull; j < number_of_simd_; ++j) {
            if (bit_vector_selection[j])
              EXPECT_EQ(wire_single->GetPublicValues()[j], global_input1.at(i)[j]);
            else
              EXPECT_EQ(wire_single->GetPublicValues()[j], global_input2.at(i)[j]);
          }
        }
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TEST_P(BmrHeavyTest, Eq) {
  EXPECT_NE(number_of_parties_, 0);
  EXPECT_NE(number_of_wires_, 0);
  EXPECT_NE(number_of_simd_, 0);

  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  std::size_t input_owner0 = std::rand() % number_of_parties_, input_owner1 = input_owner0;
  while (input_owner0 == input_owner1) input_owner1 = std::rand() % number_of_parties_;
  const std::size_t output_owner{std::rand() % number_of_parties_};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(number_of_parties_);
  for (auto& bv_v : global_input) {
    bv_v.resize(number_of_wires_);
    for (auto& bv : bv_v) {
      bv = encrypto::motion::BitVector<>::SecureRandom(number_of_simd_);
    }
  }
  if (number_of_wires_ > 1u) {  // to guarantee that at least one EQ result is true
    global_input.at(0).at(0).Set(true);
    global_input.at(1).at(0).Set(true);
  }
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      number_of_wires_, encrypto::motion::BitVector<>(number_of_simd_, false));

  try {
    std::vector<PartyPointer> motion_parties(
        MakeLocallyConnectedParties(number_of_parties_, kPortOffset));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, input_owner0, input_owner1, &motion_parties, this,
                            output_owner, &global_input, &dummy_input]() {
        std::vector<encrypto::motion::ShareWrapper> share_input;

        for (const auto input_owner : {input_owner0, input_owner1}) {
          if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            share_input.push_back(
                motion_parties.at(party_id)->In<kBmr>(global_input.at(input_owner), input_owner));
          } else {
            share_input.push_back(motion_parties.at(party_id)->In<kBmr>(dummy_input, input_owner));
          }
        }

        auto share_equal = (share_input.at(0) == share_input.at(1));

        auto share_output = share_equal.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto j = 0ull; j < share_output->GetWires().size(); ++j) {
            auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
                share_output->GetWires().at(j));
            assert(wire_single);

            std::vector<encrypto::motion::BitVector<>> eq_check_v(this->number_of_wires_);
            for (auto wire_i = 0ull; wire_i < this->number_of_wires_; ++wire_i) {
              for (auto simd_i = 0ull; simd_i < this->number_of_simd_; ++simd_i) {
                eq_check_v.at(wire_i).Append(global_input.at(input_owner0).at(wire_i)[simd_i] ==
                                             global_input.at(input_owner1).at(wire_i)[simd_i]);
              }
            }

            auto eq_check = eq_check_v.at(0);
            for (auto wire_i = 1ull; wire_i < this->number_of_wires_; ++wire_i)
              eq_check &= eq_check_v.at(wire_i);

            EXPECT_EQ(wire_single->GetPublicValues(), eq_check);
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

constexpr std::array<std::size_t, 2> kBmrAndNumberOfParties{2, 3};
constexpr std::array<std::size_t, 3> kBmrAndNumberOfWires{1, 10, 64};
constexpr std::array<std::size_t, 3> kBmrAndNumberOfSimd{1, 10, 64};
constexpr std::array<bool, 2> kBmrAndOnlineAfterSetup{false, true};

INSTANTIATE_TEST_SUITE_P(BMRHeavyTestSuite, BmrHeavyTest,
                         testing::Combine(testing::ValuesIn(kBmrAndNumberOfParties),
                                          testing::ValuesIn(kBmrAndNumberOfWires),
                                          testing::ValuesIn(kBmrAndNumberOfSimd),
                                          testing::ValuesIn(kBmrAndOnlineAfterSetup)),
                         [](const testing::TestParamInfo<BmrTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
                           std::string name = fmt::format(
                               "{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                               std::get<1>(info.param), std::get<2>(info.param), mode);
                           return name;
                         });
}  // namespace
