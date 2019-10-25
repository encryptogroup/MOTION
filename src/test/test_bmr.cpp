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
    std::vector<PartyPtr> motion_parties(
        std::move(GetNLocalParties(this->n_parties_, PORT_OFFSET)));
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
        EXPECT_EQ(s_in->GetBitLength(), this->n_wires_);
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

TEST_P(BMRTest, INV) {
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(std::time(nullptr));
  const std::size_t input_owner = std::rand() % this->n_parties_,
                    output_owner = std::rand() % this->n_parties_;
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(this->n_parties_);
  for (auto &bv_v : global_input) {
    bv_v.resize(this->n_wires_);
    for (auto &bv : bv_v) bv = ENCRYPTO::BitVector<>::Random(this->n_simd_);
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(this->n_wires_,
                                                 ENCRYPTO::BitVector<>(this->n_simd_, false));

  try {
    std::vector<PartyPtr> motion_parties(
        std::move(GetNLocalParties(this->n_parties_, PORT_OFFSET)));
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
        s_in = ~s_in;
        auto s_out = s_in.Out(output_owner);

        motion_parties.at(party_id)->Run(2);

        if (party_id == output_owner) {
          for (auto i = 0ull; i < n_wires_; ++i) {
            auto wire_single =
                std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(i));
            assert(wire_single);
            EXPECT_EQ(wire_single->GetPublicValues(), ~global_input.at(input_owner).at(i));
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
    std::vector<PartyPtr> motion_parties(
        std::move(GetNLocalParties(this->n_parties_, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back(
          [party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
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

constexpr std::array<std::size_t, 2> bmr_n_parties{2, 5};
constexpr std::array<std::size_t, 2> bmr_n_wires{1, 64};
constexpr std::array<std::size_t, 2> bmr_n_simd{1, 64};
constexpr std::array<bool, 2> bmr_online_after_setup{false, true};

INSTANTIATE_TEST_SUITE_P(
    BMRTestSuite, BMRTest,
    testing::Combine(testing::ValuesIn(bmr_n_parties), testing::ValuesIn(bmr_n_wires),
                     testing::ValuesIn(bmr_n_simd), testing::ValuesIn(bmr_online_after_setup)),
    [](const testing::TestParamInfo<BMRTest::ParamType> &info) {
      const auto mode = static_cast<bool>(std::get<3>(info.param)) ? "Seq" : "Par";
      std::string name = fmt::format("{}_Parties_{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                                     std::get<1>(info.param), std::get<2>(info.param), mode);
      return name;
    });

class BMRHeavyTest : public testing::TestWithParam<parameters_t> {
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

TEST_P(BMRHeavyTest, AND) {
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
      t.emplace_back(
          [party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
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


TEST_P(BMRHeavyTest, OR) {
  EXPECT_NE(n_parties_, 0);
  EXPECT_NE(n_wires_, 0);
  EXPECT_NE(n_simd_, 0);

  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(0);
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
      t.emplace_back(
          [party_id, &motion_parties, this, output_owner, &global_input, &dummy_input]() {
            std::vector<MOTION::Shares::ShareWrapper> s_in;

            for (auto j = 0ull; j < this->n_parties_; ++j) {
              if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
                s_in.push_back(motion_parties.at(party_id)->IN<BMR>(global_input.at(j), j));
              } else {
                s_in.push_back(motion_parties.at(party_id)->IN<BMR>(dummy_input, j));
              }
            }

            auto s_or = s_in.at(0) | s_in.at(1);

            for (auto j = 2ull; j < this->n_parties_; ++j) {
              s_or = s_or | s_in.at(j);
            }

            auto s_out = s_or.Out(output_owner);

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
                          ENCRYPTO::BitVector<>::ORBitVectors(global_input_single));
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

TEST_P(BMRHeavyTest, MUX) {
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(std::time(nullptr));
  const std::size_t in1_owner = std::rand() % this->n_parties_,
                    in2_owner = std::rand() % this->n_parties_,
                    sel_bit_owner = std::rand() % this->n_parties_,
                    output_owner = std::rand() % this->n_parties_;
  std::vector<ENCRYPTO::BitVector<>> global_in1(this->n_wires_), global_in2(this->n_wires_);
  for (auto &bv : global_in1) bv = ENCRYPTO::BitVector<>::Random(this->n_simd_);
  for (auto &bv : global_in2) bv = ENCRYPTO::BitVector<>::Random(this->n_simd_);
  ENCRYPTO::BitVector<> bv_sel = ENCRYPTO::BitVector<>::Random(this->n_simd_);

  std::vector<ENCRYPTO::BitVector<>> dummy_input(this->n_wires_,
                                                 ENCRYPTO::BitVector<>(this->n_simd_, false));
  ENCRYPTO::BitVector<> dummy_sel(this->n_simd_);

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(this->n_parties_, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, this, in1_owner, in2_owner, sel_bit_owner,
                    output_owner, &global_in1, &global_in2, &bv_sel, &dummy_input, &dummy_sel]() {
      const auto my_id = motion_parties.at(party_id)->GetConfiguration()->GetMyId();
      Shares::SharePtr s_in1;
      if (in1_owner == my_id) {
        s_in1 = motion_parties.at(party_id)->IN<BMR>(global_in1, in1_owner);
      } else {
        s_in1 = motion_parties.at(party_id)->IN<BMR>(dummy_input, in1_owner);
      }

      Shares::SharePtr s_in2;
      if (in2_owner == my_id) {
        s_in2 = motion_parties.at(party_id)->IN<BMR>(global_in2, in2_owner);
      } else {
        s_in2 = motion_parties.at(party_id)->IN<BMR>(dummy_input, in2_owner);
      }

      Shares::SharePtr s_sel;
      if (sel_bit_owner == my_id) {
        s_sel = motion_parties.at(party_id)->IN<BMR>(bv_sel, sel_bit_owner);
      } else {
        s_sel = motion_parties.at(party_id)->IN<BMR>(dummy_sel, sel_bit_owner);
      }

      MOTION::Shares::ShareWrapper sw_in1(s_in1), sw_in2(s_in2), sw_sel(s_sel);

      // sw_sel ? sw_in_1 : sw_in_2
      auto sw_res = sw_sel.MUX(sw_in1, sw_in2);

      auto sw_out = sw_res.Out(output_owner);

      motion_parties.at(party_id)->Run();

      if (party_id == output_owner) {
        for (auto i = 0ull; i < n_wires_; ++i) {
          auto wire_single =
              std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(sw_out->GetWires().at(i));
          assert(wire_single);
          for (auto j = 0ull; j < n_simd_; ++j) {
            if (bv_sel[j])
              EXPECT_EQ(wire_single->GetPublicValues()[j], global_in1.at(i)[j]);
            else
              EXPECT_EQ(wire_single->GetPublicValues()[j], global_in2.at(i)[j]);
          }
        }
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TEST_P(BMRHeavyTest, EQ) {
  EXPECT_NE(n_parties_, 0);
  EXPECT_NE(n_wires_, 0);
  EXPECT_NE(n_simd_, 0);

  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::srand(0);
  std::size_t input_owner0 = std::rand() % n_parties_, input_owner1 = input_owner0;
  while (input_owner0 == input_owner1) input_owner1 = std::rand() % n_parties_;
  const std::size_t output_owner{std::rand() % n_parties_};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(n_parties_);
  for (auto &bv_v : global_input) {
    bv_v.resize(n_wires_);
    for (auto &bv : bv_v) {
      bv = ENCRYPTO::BitVector<>::Random(n_simd_);
    }
  }
  if (n_wires_ > 1u) {  // to guarantee that at least one EQ result is true
    global_input.at(0).at(0).Set(true);
    global_input.at(1).at(0).Set(true);
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires_, ENCRYPTO::BitVector<>(n_simd_, false));

  try {
    std::vector<PartyPtr> motion_parties(GetNLocalParties(n_parties_, PORT_OFFSET));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back([party_id, input_owner0, input_owner1, &motion_parties, this, output_owner,
                      &global_input, &dummy_input]() {
        std::vector<MOTION::Shares::ShareWrapper> s_in;

        for (const auto input_owner : {input_owner0, input_owner1}) {
          if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            s_in.push_back(
                motion_parties.at(party_id)->IN<BMR>(global_input.at(input_owner), input_owner));
          } else {
            s_in.push_back(motion_parties.at(party_id)->IN<BMR>(dummy_input, input_owner));
          }
        }

        auto s_eq = (s_in.at(0) == s_in.at(1));

        auto s_out = s_eq.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto j = 0ull; j < s_out->GetWires().size(); ++j) {
            auto wire_single =
                std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(j));
            assert(wire_single);

            std::vector<ENCRYPTO::BitVector<>> eq_check_v(this->n_wires_);
            for (auto wire_i = 0ull; wire_i < this->n_wires_; ++wire_i) {
              for (auto simd_i = 0ull; simd_i < this->n_simd_; ++simd_i) {
                eq_check_v.at(wire_i).Append(global_input.at(input_owner0).at(wire_i)[simd_i] ==
                                             global_input.at(input_owner1).at(wire_i)[simd_i]);
              }
            }

            auto eq_check = eq_check_v.at(0);
            for (auto wire_i = 1ull; wire_i < this->n_wires_; ++wire_i)
              eq_check &= eq_check_v.at(wire_i);

            EXPECT_EQ(wire_single->GetPublicValues(), eq_check);
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

INSTANTIATE_TEST_SUITE_P(BMRHeavyTestSuite, BMRHeavyTest,
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
