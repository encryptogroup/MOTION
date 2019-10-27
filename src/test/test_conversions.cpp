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
using conv_parameters_t = std::tuple<std::size_t, std::size_t, std::size_t, bool>;

class ConversionTest : public testing::TestWithParam<conv_parameters_t> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(num_parties_, num_wires_, num_simd_, online_after_setup_) = parameters;
  }
  void TearDown() override { num_parties_ = num_wires_ = num_simd_ = 0; }

 protected:
  std::size_t num_parties_ = 0, num_wires_ = 0, num_simd_ = 0;
  bool online_after_setup_ = false;
};

TEST_P(ConversionTest, Y2B) {
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(0);
  const std::size_t input_owner = std::rand() % this->num_parties_,
                    output_owner = std::rand() % this->num_parties_;
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(this->num_parties_);
  for (auto &bv_v : global_input) {
    bv_v.resize(this->num_wires_);
    for (auto &bv : bv_v) {
      bv = ENCRYPTO::BitVector<>::Random(this->num_simd_);
    }
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(this->num_wires_,
                                                 ENCRYPTO::BitVector<>(this->num_simd_, false));

  try {
    std::vector<PartyPtr> motion_parties(
        std::move(GetNLocalParties(this->num_parties_, PORT_OFFSET)));
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
          tmp_share =
              motion_parties.at(party_id)->IN<BMR>(global_input.at(input_owner), input_owner);
        } else {
          tmp_share = motion_parties.at(party_id)->IN<BMR>(dummy_input, input_owner);
        }

        MOTION::Shares::ShareWrapper s_in(tmp_share);
        EXPECT_EQ(s_in->GetBitLength(), this->num_wires_);
        const auto s_conv{s_in.Convert<MPCProtocol::BooleanGMW>()};
        auto s_out{s_conv.Out(output_owner)};

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto i = 0ull; i < this->num_wires_; ++i) {
            auto wire_single{
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(i))};
            assert(wire_single);
            EXPECT_EQ(wire_single->GetValues(), global_input.at(input_owner).at(i));
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

TEST_P(ConversionTest, B2Y) {
  constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
  std::srand(0);
  const std::size_t input_owner = std::rand() % this->num_parties_,
                    output_owner = std::rand() % this->num_parties_;
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(this->num_parties_);
  for (auto &bv_v : global_input) {
    bv_v.resize(this->num_wires_);
    for (auto &bv : bv_v) {
      bv = ENCRYPTO::BitVector<>::Random(this->num_simd_);
    }
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(this->num_wires_,
                                                 ENCRYPTO::BitVector<>(this->num_simd_, false));

  try {
    std::vector<PartyPtr> motion_parties(
        std::move(GetNLocalParties(this->num_parties_, PORT_OFFSET)));
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
          tmp_share =
              motion_parties.at(party_id)->IN<BGMW>(global_input.at(input_owner), input_owner);
        } else {
          tmp_share = motion_parties.at(party_id)->IN<BGMW>(dummy_input, input_owner);
        }

        MOTION::Shares::ShareWrapper s_in(tmp_share);
        EXPECT_EQ(s_in->GetBitLength(), this->num_wires_);
        const auto s_conv{s_in.Convert<MPCProtocol::BMR>()};
        auto s_out{s_conv.Out(output_owner)};

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto i = 0ull; i < this->num_wires_; ++i) {
            auto wire_single{
                std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(i))};
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

constexpr std::array<std::size_t, 2> conv_num_parties{2, 3};
constexpr std::array<std::size_t, 3> conv_num_wires{1, 10, 64};
constexpr std::array<std::size_t, 3> conv_num_simd{1, 10, 64};
constexpr std::array<bool, 2> conv_online_after_setup{false, true};

INSTANTIATE_TEST_SUITE_P(
    ConversionTestSuite, ConversionTest,
    testing::Combine(testing::ValuesIn(conv_num_parties), testing::ValuesIn(conv_num_wires),
                     testing::ValuesIn(conv_num_simd), testing::ValuesIn(conv_online_after_setup)),
    [](const testing::TestParamInfo<ConversionTest::ParamType> &info) {
      const auto mode = static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
      std::string name = fmt::format("{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                                     std::get<1>(info.param), std::get<2>(info.param), mode);
      return name;
    });

}  // namespace
