// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include <gtest/gtest.h>
#include "base/party.h"
#include "gate/boolean_gmw_gate.h"
#include "share/share_wrapper.h"
#include "test_constants.h"
#include "test_helpers.h"
#include "wire/boolean_gmw_wire.h"

using namespace MOTION;

TEST(BooleanGMW, InputOutput_1_1K_SIMD_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t input_owner = std::rand() % num_parties,
                        output_owner = std::rand() % num_parties;
      const auto global_input_1 = (std::rand() % 2) == 1;
      const auto global_input_1K = ENCRYPTO::BitVector<>::Random(1000);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          bool input_1 = false;
          ENCRYPTO::BitVector<> input_1K(global_input_1K.GetSize(), false);
          if (party_id == input_owner) {
            input_1 = global_input_1;
            input_1K = global_input_1K;
          }

          MOTION::Shares::ShareWrapper s_in_1 =
              motion_parties.at(party_id)->IN<BGMW>(input_1, input_owner);
          MOTION::Shares::ShareWrapper s_in_1K =
              motion_parties.at(party_id)->IN<BGMW>(input_1K, input_owner);

          auto s_out_1 = s_in_1.Out(output_owner);
          auto s_out_1K = s_in_1K.Out(output_owner);

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0), global_input_1);
            EXPECT_EQ(wire_1K->GetValues(), global_input_1K);
          }
          motion_parties.at(party_id).reset();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, INV_1K_SIMD_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t input_owner = std::rand() % num_parties,
                        output_owner = std::rand() % num_parties;
      const auto global_input_1K = ENCRYPTO::BitVector<>::Random(1000);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          ENCRYPTO::BitVector<> input_1K(global_input_1K.GetSize(), false);
          if (party_id == input_owner) {
            input_1K = global_input_1K;
          }

          MOTION::Shares::ShareWrapper s_in_1K =
              motion_parties.at(party_id)->IN<BGMW>(input_1K, input_owner);

          s_in_1K = ~s_in_1K;

          auto s_out_1K = s_in_1K.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K->GetWires().at(0));

            assert(wire_1K);

            EXPECT_EQ(wire_1K->GetValues(), ~global_input_1K);
          }
          motion_parties.at(party_id).reset();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, XOR_64_bit_200_SIMD_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input_200_64_bit(num_parties);
      for (auto &bv_v : global_input_200_64_bit) {
        bv_v.resize(64);
        for (auto &bv : bv_v) {
          bv = ENCRYPTO::BitVector<>::Random(200);
        }
      }
      std::vector<ENCRYPTO::BitVector<>> dummy_input_200_64_bit(64,
                                                                ENCRYPTO::BitVector<>(200, false));

      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in.push_back(
                  motion_parties.at(party_id)->IN<BGMW>(global_input_200_64_bit.at(j), j));
            } else {
              s_in.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_200_64_bit, j));
            }
          }

          auto s_xor = s_in.at(0) ^ s_in.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_xor = s_xor ^ s_in.at(j);
          }

          auto s_out = s_xor.Out(output_owner);

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_200_64_bit.size(); ++j) {
              auto wire_200_64_bit_single =
                  std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(j));
              assert(wire_200_64_bit_single);

              std::vector<ENCRYPTO::BitVector<>> global_input_200_64_bit_single;
              for (auto k = 0ull; k < num_parties; ++k) {
                global_input_200_64_bit_single.push_back(global_input_200_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_200_64_bit_single->GetValues(),
                        ENCRYPTO::BitVector<>::XORBitVectors(global_input_200_64_bit_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, MUX_1K_SIMD_2_3_parties) {
  constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
  std::srand(std::time(nullptr));
  for (auto num_parties : {2u, 3u}) {
    const std::size_t in1_owner = std::rand() % num_parties, in2_owner = std::rand() % num_parties,
                      sel_bit_owner = std::rand() % num_parties,
                      output_owner = std::rand() % num_parties;

    ENCRYPTO::BitVector<> global_input_1K_a{ENCRYPTO::BitVector<>::Random(1000)},
        global_input_1K_b{ENCRYPTO::BitVector<>::Random(1000)},
        global_input_1K_sel{ENCRYPTO::BitVector<>::Random(1000)};

    ENCRYPTO::BitVector<> dummy_input_1K(1000, false);
    std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(true);
    }

    auto f = [&](std::size_t party_id) {
      MOTION::Shares::ShareWrapper s_in_1K_a =
          party_id == in1_owner
              ? motion_parties.at(party_id)->IN<BGMW>(global_input_1K_a, in1_owner)
              : motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, in1_owner);
      MOTION::Shares::ShareWrapper s_in_1K_b =
          party_id == in2_owner
              ? motion_parties.at(party_id)->IN<BGMW>(global_input_1K_b, in2_owner)
              : motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, in2_owner);
      MOTION::Shares::ShareWrapper s_in_1K_sel =
          party_id == sel_bit_owner
              ? motion_parties.at(party_id)->IN<BGMW>(global_input_1K_sel, sel_bit_owner)
              : motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, sel_bit_owner);

      auto s_selected = s_in_1K_sel.MUX(s_in_1K_a, s_in_1K_b);

      auto s_out_1K_all = s_selected.Out();

      motion_parties.at(party_id)->Run();

      {
        auto wire_1K =
            std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K_all->GetWires().at(0));

        assert(wire_1K);

        for (auto simd_i = 0ull; simd_i < global_input_1K_sel.GetSize(); ++simd_i) {
          if (global_input_1K_sel[simd_i])
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_a[simd_i]);
          else
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_b[simd_i]);
        }
      }

      motion_parties.at(party_id)->Finish();
    };
    std::vector<std::thread> t;
    for (auto &p : motion_parties) {
      const auto party_id = p->GetBackend()->GetConfig()->GetMyId();
      t.emplace_back(std::bind(f, party_id));
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  }
}

TEST(BooleanGMW, MUX_1K_SIMD_64_wires_2_3_parties) {
  constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
  std::srand(std::time(nullptr));
  for (auto num_parties : {2u, 3u}) {
    const std::size_t in1_owner = std::rand() % num_parties, in2_owner = std::rand() % num_parties,
                      sel_bit_owner = std::rand() % num_parties,
                      output_owner = std::rand() % num_parties;

    std::vector<ENCRYPTO::BitVector<>> global_input_1K_a(64, ENCRYPTO::BitVector<>::Random(1000)),
        global_input_1K_b(64, ENCRYPTO::BitVector<>::Random(1000));
    ENCRYPTO::BitVector<> global_input_1K_sel{ENCRYPTO::BitVector<>::Random(1000)};

    std::vector<ENCRYPTO::BitVector<>> dummy_input_1K(64, ENCRYPTO::BitVector<>(1000));
    ENCRYPTO::BitVector<> dummy_input_1K_sel(1000, false);
    std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(true);
    }

    auto f = [&](std::size_t party_id) {
      MOTION::Shares::ShareWrapper s_in_1K_a =
          party_id == in1_owner
              ? motion_parties.at(party_id)->IN<BGMW>(global_input_1K_a, in1_owner)
              : motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, in1_owner);
      MOTION::Shares::ShareWrapper s_in_1K_b =
          party_id == in2_owner
              ? motion_parties.at(party_id)->IN<BGMW>(global_input_1K_b, in2_owner)
              : motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, in2_owner);
      MOTION::Shares::ShareWrapper s_in_1K_sel =
          party_id == sel_bit_owner
              ? motion_parties.at(party_id)->IN<BGMW>(global_input_1K_sel, sel_bit_owner)
              : motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K_sel, sel_bit_owner);

      auto s_selected = s_in_1K_sel.MUX(s_in_1K_a, s_in_1K_b);

      auto s_out_1K_all = s_selected.Out();

      motion_parties.at(party_id)->Run();

      for (auto i = 0; i < 64; ++i) {
        auto wire_1K =
            std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K_all->GetWires().at(i));

        assert(wire_1K);

        for (auto simd_i = 0ull; simd_i < global_input_1K_sel.GetSize(); ++simd_i) {
          if (global_input_1K_sel[simd_i])
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_a.at(i)[simd_i]);
          else
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_b.at(i)[simd_i]);
        }
      }

      motion_parties.at(party_id)->Finish();
    };
    std::vector<std::thread> t;
    for (auto &p : motion_parties) {
      const auto party_id = p->GetBackend()->GetConfig()->GetMyId();
      t.emplace_back(std::bind(f, party_id));
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  }
}

TEST(BooleanGMW, EQ_1_bit_1K_SIMD_2_3_parties) {
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::srand(0);
  constexpr std::size_t n_simd{1000}, n_wires{1};
  for (auto num_parties : {2u, 3u}) {
    std::size_t input_owner0 = std::rand() % num_parties, input_owner1 = input_owner0;
    while (input_owner0 == input_owner1) input_owner1 = std::rand() % num_parties;
    const std::size_t output_owner{std::rand() % num_parties};
    std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(num_parties);
    for (auto &bv_v : global_input) {
      bv_v.resize(n_wires);
      for (auto &bv : bv_v) {
        bv = ENCRYPTO::BitVector<>::Random(n_simd);
      }
    }
    std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

    std::vector<PartyPtr> motion_parties(GetNLocalParties(num_parties, PORT_OFFSET));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back([n_simd, n_wires, party_id, input_owner0, input_owner1, &motion_parties, this,
                      output_owner, &global_input, &dummy_input]() {
        std::vector<MOTION::Shares::ShareWrapper> s_in;

        for (const auto input_owner : {input_owner0, input_owner1}) {
          if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            s_in.push_back(
                motion_parties.at(party_id)->IN<GMW>(global_input.at(input_owner), input_owner));
          } else {
            s_in.push_back(motion_parties.at(party_id)->IN<GMW>(dummy_input, input_owner));
          }
        }

        auto s_eq = (s_in.at(0) == s_in.at(1));

        auto s_out = s_eq.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto j = 0ull; j < s_out->GetWires().size(); ++j) {
            auto wire_single =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(j));
            assert(wire_single);

            std::vector<ENCRYPTO::BitVector<>> eq_check_v(n_wires);
            for (auto wire_i = 0ull; wire_i < n_wires; ++wire_i) {
              for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
                eq_check_v.at(wire_i).Append(global_input.at(input_owner0).at(wire_i)[simd_i] ==
                                             global_input.at(input_owner1).at(wire_i)[simd_i]);
              }
            }

            auto eq_check = eq_check_v.at(0);
            for (auto wire_i = 1ull; wire_i < n_wires; ++wire_i) eq_check &= eq_check_v.at(wire_i);

            EXPECT_EQ(wire_single->GetValues(), eq_check);
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  }
}

TEST(BooleanGMW, EQ_64_bit_10_SIMD_2_3_parties) {
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::srand(0);
  constexpr std::size_t n_simd{10}, n_wires{64};
  for (auto num_parties : {2u, 3u}) {
    std::size_t input_owner0 = std::rand() % num_parties, input_owner1 = input_owner0;
    while (input_owner0 == input_owner1) input_owner1 = std::rand() % num_parties;
    const std::size_t output_owner{std::rand() % num_parties};
    std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input(num_parties);
    for (auto &bv_v : global_input) {
      bv_v.resize(n_wires);
      for (auto &bv : bv_v) {
        bv = ENCRYPTO::BitVector<>::Random(n_simd);
      }
    }

    // to guarantee that at least one EQ result is true
    global_input.at(0).at(0).Set(true);
    global_input.at(1).at(0).Set(true);

    std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

    std::vector<PartyPtr> motion_parties(GetNLocalParties(num_parties, PORT_OFFSET));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back([party_id, input_owner0, input_owner1, &motion_parties, this, output_owner,
                      &global_input, &dummy_input]() {
        std::vector<MOTION::Shares::ShareWrapper> s_in;

        for (const auto input_owner : {input_owner0, input_owner1}) {
          if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            s_in.push_back(
                motion_parties.at(party_id)->IN<GMW>(global_input.at(input_owner), input_owner));
          } else {
            s_in.push_back(motion_parties.at(party_id)->IN<GMW>(dummy_input, input_owner));
          }
        }

        auto s_eq = (s_in.at(0) == s_in.at(1));

        auto s_out = s_eq.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto j = 0ull; j < s_out->GetWires().size(); ++j) {
            auto wire_single =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(j));
            assert(wire_single);

            std::vector<ENCRYPTO::BitVector<>> eq_check_v(n_wires);
            for (auto wire_i = 0ull; wire_i < n_wires; ++wire_i) {
              for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
                eq_check_v.at(wire_i).Append(global_input.at(input_owner0).at(wire_i)[simd_i] ==
                                             global_input.at(input_owner1).at(wire_i)[simd_i]);
              }
            }

            auto eq_check = eq_check_v.at(0);
            for (auto wire_i = 1ull; wire_i < n_wires; ++wire_i) eq_check &= eq_check_v.at(wire_i);

            EXPECT_EQ(wire_single->GetValues(), eq_check);
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  }
}

TEST(BooleanGMW, AND_1_bit_1_1K_SIMD_2_3_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<bool> global_input_1(num_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<ENCRYPTO::BitVector<>> global_input_1K(num_parties);

      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = ENCRYPTO::BitVector<>::Random(1000);
      }
      bool dummy_input_1 = false;
      ENCRYPTO::BitVector<> dummy_input_1K(1000, false);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }

        auto f = [&](std::size_t party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in_1.push_back(motion_parties.at(party_id)->IN<BGMW>(
                  static_cast<bool>(global_input_1.at(j)), j));
              s_in_1K.push_back(motion_parties.at(party_id)->IN<BGMW>(global_input_1K.at(j), j));
            } else {
              s_in_1.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_1, j));
              s_in_1K.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, j));
            }
          }

          auto s_and_1 = s_in_1.at(0) & s_in_1.at(1);
          auto s_and_1K = s_in_1K.at(0) & s_in_1K.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_and_1 = s_and_1 & s_in_1.at(j);
            s_and_1K = s_and_1K & s_in_1K.at(j);
          }

          auto s_out_1 = s_and_1.Out(output_owner);
          auto s_out_1K = s_and_1K.Out(output_owner);

          auto s_out_1_all = s_and_1.Out();
          auto s_out_1K_all = s_and_1K.Out();

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      ENCRYPTO::BitVector<>::ANDReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(), ENCRYPTO::BitVector<>::ANDBitVectors(global_input_1K));
          }

          {
            auto wire_1 =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1_all->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K_all->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      ENCRYPTO::BitVector<>::ANDReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(), ENCRYPTO::BitVector<>::ANDBitVectors(global_input_1K));
          }
        };

#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          f(party_id);
          // check multiplication triples
          if (party_id == 0) {
            ENCRYPTO::BitVector<> a, b, c;
            a = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
            b = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
            c = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().c;

            for (auto j = 1ull; j < motion_parties.size(); ++j) {
              a ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
              b ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
              c ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().c;
            }
            EXPECT_EQ(c, a & b);
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, AND_64_bit_10_SIMD_2_3_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input_10_64_bit(num_parties);
      for (auto &bv_v : global_input_10_64_bit) {
        bv_v.resize(64);
        for (auto &bv : bv_v) {
          bv = ENCRYPTO::BitVector<>::Random(10);
        }
      }
      std::vector<ENCRYPTO::BitVector<>> dummy_input_10_64_bit(64,
                                                               ENCRYPTO::BitVector<>(10, false));

      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in.push_back(
                  motion_parties.at(party_id)->IN<BGMW>(global_input_10_64_bit.at(j), j));
            } else {
              s_in.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_10_64_bit, j));
            }
          }

          auto s_and = s_in.at(0) & s_in.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_and = s_and & s_in.at(j);
          }

          auto s_out = s_and.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_10_64_bit.size(); ++j) {
              auto wire_single =
                  std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(j));
              assert(wire_single);

              std::vector<ENCRYPTO::BitVector<>> global_input_single;
              for (auto k = 0ull; k < num_parties; ++k) {
                global_input_single.push_back(global_input_10_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_single->GetValues(),
                        ENCRYPTO::BitVector<>::ANDBitVectors(global_input_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, OR_1_bit_1_1K_SIMD_2_3_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<bool> global_input_1(num_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<ENCRYPTO::BitVector<>> global_input_1K(num_parties);

      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = ENCRYPTO::BitVector<>::Random(1000);
      }
      bool dummy_input_1 = false;
      ENCRYPTO::BitVector<> dummy_input_1K(1000, false);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }

        auto f = [&](std::size_t party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in_1.push_back(motion_parties.at(party_id)->IN<BGMW>(
                  static_cast<bool>(global_input_1.at(j)), j));
              s_in_1K.push_back(motion_parties.at(party_id)->IN<BGMW>(global_input_1K.at(j), j));
            } else {
              s_in_1.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_1, j));
              s_in_1K.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, j));
            }
          }

          auto s_or_1 = s_in_1.at(0) | s_in_1.at(1);
          auto s_or_1K = s_in_1K.at(0) | s_in_1K.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_or_1 = s_or_1 | s_in_1.at(j);
            s_or_1K = s_or_1K | s_in_1K.at(j);
          }

          auto s_out_1_all = s_or_1.Out();
          auto s_out_1K_all = s_or_1K.Out();

          motion_parties.at(party_id)->Run();

          {
            auto wire_1 =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1_all->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K_all->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      ENCRYPTO::BitVector<>::ORReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(), ENCRYPTO::BitVector<>::ORBitVectors(global_input_1K));
          }
          motion_parties.at(party_id)->Finish();
        };

#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          f(party_id);
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, OR_64_bit_10_SIMD_2_3_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input_10_64_bit(num_parties);
      for (auto &bv_v : global_input_10_64_bit) {
        bv_v.resize(64);
        for (auto &bv : bv_v) {
          bv = ENCRYPTO::BitVector<>::Random(10);
        }
      }
      std::vector<ENCRYPTO::BitVector<>> dummy_input_10_64_bit(64,
                                                               ENCRYPTO::BitVector<>(10, false));

      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in.push_back(
                  motion_parties.at(party_id)->IN<BGMW>(global_input_10_64_bit.at(j), j));
            } else {
              s_in.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_10_64_bit, j));
            }
          }

          auto s_or = s_in.at(0) | s_in.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_or = s_or | s_in.at(j);
          }

          auto s_out = s_or.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_10_64_bit.size(); ++j) {
              auto wire_single =
                  std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(j));
              assert(wire_single);

              std::vector<ENCRYPTO::BitVector<>> global_input_single;
              for (auto k = 0ull; k < num_parties; ++k) {
                global_input_single.push_back(global_input_10_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_single->GetValues(),
                        ENCRYPTO::BitVector<>::ORBitVectors(global_input_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}
