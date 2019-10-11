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
#include "crypto/multiplication_triple/mt_provider.h"
#include "share/share_wrapper.h"
#include "utility/typedefs.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

#include "test_constants.h"

namespace {
using namespace MOTION;

// number of parties, wires, SIMD values, online-after-setup flag
using parameters_t = std::tuple<std::size_t, std::size_t, std::size_t, bool>;

class BMRTest : public testing::TestWithParam<parameters_t> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(n_parties_, n_wires_, n_simd_, online_after_setup_) = parameters;
  }
  void TearDown() override { n_parties_ = n_wires_ = n_simd_ = 0; }

 protected:
  std::size_t n_parties_ = 0, n_wires_ = 0, n_simd_ = 0;
  bool online_after_setup_ = false;
};

TEST_P(BMRTest, InputOutput) {
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(std::time(nullptr));
  const std::size_t input_owner = std::rand() % this->n_parties_,
                    output_owner = std::rand() % this->n_parties_;
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(this->n_parties_);
  for (auto &bv_v : global_input) {
    bv_v.resize(this->n_wires_);
    for (auto &bv : bv_v) {
      bv = ENCRYPTO::BitVector<>::Random(this->n_simd_);
    }
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(this->n_wires_,
                                                 ENCRYPTO::BitVector<>(this->n_simd_, false));

  try {
    std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(this->n_parties_, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back([party_id, &motion_parties, this, input_owner, output_owner, &global_input,
                      &dummy_input]() {
        Shares::SharePtr tmp_share;
        if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
          tmp_share = motion_parties.at(party_id)->IN<BMR>(global_input.at(input_owner), input_owner);
        } else {
          tmp_share = motion_parties.at(party_id)->IN<BMR>(dummy_input, input_owner);
        }

        MOTION::Shares::ShareWrapper s_in(tmp_share);

        auto s_out = s_in.Out(output_owner);

        motion_parties.at(party_id)->Run(2);

        if (party_id == output_owner) {
          for (auto i = 0ull; i < n_wires_; ++i) {
            auto wire_single =
                std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(i));
            assert(wire_single);
            EXPECT_EQ(wire_single->GetPublicValues(), global_input.at(input_owner).at(i));
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(BMRTest, XOR) {
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(std::time(nullptr));
  const std::size_t output_owner = std::rand() % this->n_parties_;
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(this->n_parties_);
  for (auto &bv_v : global_input) {
    bv_v.resize(this->n_wires_);
    for (auto &bv : bv_v) {
      bv = ENCRYPTO::BitVector<>::Random(this->n_simd_);
    }
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(this->n_wires_,
                                                 ENCRYPTO::BitVector<>(this->n_simd_, false));
  try {
    std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(this->n_parties_, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back([party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
        std::vector<MOTION::Shares::ShareWrapper> s_in;

        for (auto j = 0ull; j < this->n_parties_; ++j) {
          if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            s_in.push_back(motion_parties.at(party_id)->IN<BMR>(global_input.at(j), j));
          } else {
            s_in.push_back(motion_parties.at(party_id)->IN<BMR>(dummy_input, j));
          }
        }

        auto s_xor = s_in.at(0) ^ s_in.at(1);

        for (auto j = 2ull; j < this->n_parties_; ++j) {
          s_xor = s_xor ^ s_in.at(j);
        }

        auto s_out = s_xor.Out(output_owner);

        motion_parties.at(party_id)->Run(2);

        if (party_id == output_owner) {
          for (auto j = 0ull; j < this->n_wires_; ++j) {
            auto wire_single =
                std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(j));
            assert(wire_single);

            std::vector<ENCRYPTO::BitVector<>> global_input_single;
            for (auto k = 0ull; k < this->n_parties_; ++k) {
              global_input_single.push_back(global_input.at(k).at(j));
            }

            EXPECT_EQ(wire_single->GetPublicValues(),
                      ENCRYPTO::BitVector<>::XORBitVectors(global_input_single));
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
}

constexpr std::array<std::size_t, 3> bmr_n_parties{2, 5, 10};
constexpr std::array<std::size_t, 2> bmr_n_wires{1, 64};
constexpr std::array<std::size_t, 2> bmr_n_simd{1, 64};
constexpr std::array<bool, 2> bmr_online_after_setup{false, true};

INSTANTIATE_TEST_SUITE_P(BMRXORTestSuite, BMRTest,
                         testing::Combine(testing::ValuesIn(bmr_n_parties),
                                          testing::ValuesIn(bmr_n_wires),
                                          testing::ValuesIn(bmr_n_simd),
                                          testing::ValuesIn(bmr_online_after_setup)),
                         [](const testing::TestParamInfo<BMRTest::ParamType> &info) {
                           const auto mode =
                               static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
                           std::string name = fmt::format(
                               "{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                               std::get<1>(info.param), std::get<2>(info.param), mode);
                           return name;
                         });

class BMRANDTest : public testing::TestWithParam<parameters_t> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(n_parties_, n_wires_, n_simd_, online_after_setup_) = parameters;
  }
  void TearDown() override { n_parties_ = n_wires_ = n_simd_ = 0; }

 protected:
  std::size_t n_parties_ = 0, n_wires_ = 0, n_simd_ = 0;
  bool online_after_setup_ = false;
};


TEST_P(BMRANDTest, AND) {
  EXPECT_NE(n_parties_, 0);
  EXPECT_NE(n_wires_, 0);
  EXPECT_NE(n_simd_, 0);

  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(std::time(nullptr));
  const std::size_t output_owner = std::rand() % n_parties_;
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(n_parties_);
  for (auto &bv_v : global_input) {
    bv_v.resize(n_wires_);
    for (auto &bv : bv_v) {
      bv = ENCRYPTO::BitVector<>::Random(n_simd_);
    }
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires_, ENCRYPTO::BitVector<>(n_simd_, false));

  try {
    std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(n_parties_, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back([party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
        std::vector<MOTION::Shares::ShareWrapper> s_in;

        for (auto j = 0ull; j < this->n_parties_; ++j) {
          if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            s_in.push_back(motion_parties.at(party_id)->IN<BMR>(global_input.at(j), j));
          } else {
            s_in.push_back(motion_parties.at(party_id)->IN<BMR>(dummy_input, j));
          }
        }

        auto s_and = s_in.at(0) & s_in.at(1);

        for (auto j = 2ull; j < this->n_parties_; ++j) {
          s_and = s_and & s_in.at(j);
        }

        auto s_out = s_and.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto j = 0ull; j < s_out->GetWires().size(); ++j) {
            auto wire_single =
                std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(j));
            assert(wire_single);

            std::vector<ENCRYPTO::BitVector<>> global_input_single;
            for (auto k = 0ull; k < this->n_parties_; ++k) {
              global_input_single.push_back(global_input.at(k).at(j));
            }

            EXPECT_EQ(wire_single->GetPublicValues(),
                      ENCRYPTO::BitVector<>::ANDBitVectors(global_input_single));
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
}

constexpr std::array<std::size_t, 2> bmr_and_n_parties{2, 3};
constexpr std::array<std::size_t, 3> bmr_and_n_wires{1, 10, 64};
constexpr std::array<std::size_t, 3> bmr_and_n_simd{1, 10, 64};
constexpr std::array<bool, 2> bmr_and_online_after_setup{false, true};

INSTANTIATE_TEST_SUITE_P(BMRANDTestSuite, BMRANDTest,
                         testing::Combine(testing::ValuesIn(bmr_and_n_parties),
                                          testing::ValuesIn(bmr_and_n_wires),
                                          testing::ValuesIn(bmr_and_n_simd),
                                          testing::ValuesIn(bmr_and_online_after_setup)),
                         [](const testing::TestParamInfo<BMRTest::ParamType> &info) {
                           const auto mode =
                               static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
                           std::string name = fmt::format(
                               "{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                               std::get<1>(info.param), std::get<2>(info.param), mode);
                           return name;
                         });

}  // namespace
