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
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_signed_integer.h"
#include "test_constants.h"
#include "test_helpers.h"

namespace {

using namespace encrypto::motion;

TEST(BooleanGmw, InputOutput_1_1K_Simd_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));
    for (auto number_of_parties : kNumberOfPartiesList) {
      const std::size_t input_owner = std::rand() % number_of_parties,
                        output_owner = std::rand() % number_of_parties;
      const auto global_input_1 = (std::rand() % 2) == 1;
      const auto global_input_1K = encrypto::motion::BitVector<>::SecureRandom(1000);
      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          bool input_1 = false;
          encrypto::motion::BitVector<> input_1K(global_input_1K.GetSize(), false);
          if (party_id == input_owner) {
            input_1 = global_input_1;
            input_1K = global_input_1K;
          }

          encrypto::motion::ShareWrapper share_input_1 =
              motion_parties.at(party_id)->In<kBooleanGmw>(input_1, input_owner);
          encrypto::motion::ShareWrapper share_input_1K =
              motion_parties.at(party_id)->In<kBooleanGmw>(input_1K, input_owner);

          auto share_output_1 = share_input_1.Out(output_owner);
          auto share_output_1K = share_input_1K.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0), global_input_1);
            EXPECT_EQ(wire_1K->GetValues(), global_input_1K);
          }
          motion_parties.at(party_id).reset();
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGmw, Inv_1K_Simd_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));
    for (auto number_of_parties : kNumberOfPartiesList) {
      const std::size_t input_owner = std::rand() % number_of_parties,
                        output_owner = std::rand() % number_of_parties;
      const auto global_input_1K = encrypto::motion::BitVector<>::SecureRandom(1000);
      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          encrypto::motion::BitVector<> input_1K(global_input_1K.GetSize(), false);
          if (party_id == input_owner) {
            input_1K = global_input_1K;
          }

          encrypto::motion::ShareWrapper share_input_1K =
              motion_parties.at(party_id)->In<kBooleanGmw>(input_1K, input_owner);

          share_input_1K = ~share_input_1K;

          auto share_output_1K = share_input_1K.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1K = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1K->GetWires().at(0));

            assert(wire_1K);

            EXPECT_EQ(wire_1K->GetValues(), ~global_input_1K);
          }
          motion_parties.at(party_id).reset();
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGmw, Xor_64_bit_200_Simd_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));
    for (auto number_of_parties : kNumberOfPartiesList) {
      const std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<std::vector<encrypto::motion::BitVector<>>> global_input_200_64_bit(
          number_of_parties);
      for (auto& bv_v : global_input_200_64_bit) {
        bv_v.resize(64);
        for (auto& bv : bv_v) {
          bv = encrypto::motion::BitVector<>::SecureRandom(200);
        }
      }
      std::vector<encrypto::motion::BitVector<>> dummy_input_200_64_bit(
          64, encrypto::motion::BitVector<>(200, false));

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input;

          for (auto j = 0ull; j < number_of_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              share_input.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(global_input_200_64_bit.at(j), j));
            } else {
              share_input.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_200_64_bit, j));
            }
          }

          auto share_xor = share_input.at(0) ^ share_input.at(1);

          for (auto j = 2ull; j < number_of_parties; ++j) {
            share_xor = share_xor ^ share_input.at(j);
          }

          auto share_output = share_xor.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_200_64_bit.size(); ++j) {
              auto wire_200_64_bit_single =
                  std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                      share_output->GetWires().at(j));
              assert(wire_200_64_bit_single);

              std::vector<encrypto::motion::BitVector<>> global_input_200_64_bit_single;
              for (auto k = 0ull; k < number_of_parties; ++k) {
                global_input_200_64_bit_single.push_back(global_input_200_64_bit.at(k).at(j));
              }

              EXPECT_EQ(
                  wire_200_64_bit_single->GetValues(),
                  encrypto::motion::BitVector<>::XorBitVectors(global_input_200_64_bit_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGmw, Mux_1K_Simd_2_3_parties) {
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(std::time(nullptr));
  for (auto number_of_parties : {2u, 3u}) {
    const std::size_t input1_owner = std::rand() % number_of_parties,
                      input2_owner = std::rand() % number_of_parties,
                      selection_bit_owner = std::rand() % number_of_parties,
                      output_owner = std::rand() % number_of_parties;

    encrypto::motion::BitVector<> global_input_1K_a{
        encrypto::motion::BitVector<>::SecureRandom(1000)},
        global_input_1K_b{encrypto::motion::BitVector<>::SecureRandom(1000)},
        global_input_1K_selection{encrypto::motion::BitVector<>::SecureRandom(1000)};

    encrypto::motion::BitVector<> dummy_input_1K(1000, false);
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }

    auto f = [&](std::size_t party_id) {
      encrypto::motion::ShareWrapper share_input_1K_a =
          party_id == input1_owner
              ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K_a, input1_owner)
              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K, input1_owner);
      encrypto::motion::ShareWrapper share_input_1K_b =
          party_id == input2_owner
              ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K_b, input2_owner)
              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K, input2_owner);
      encrypto::motion::ShareWrapper share_input_1K_selection =
          party_id == selection_bit_owner
              ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K_selection,
                                                             selection_bit_owner)
              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K, selection_bit_owner);

      auto share_selected = share_input_1K_selection.Mux(share_input_1K_a, share_input_1K_b);

      auto share_output_1K_all = share_selected.Out();

      motion_parties.at(party_id)->Run();

      {
        auto wire_1K = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
            share_output_1K_all->GetWires().at(0));

        assert(wire_1K);

        for (auto simd_i = 0ull; simd_i < global_input_1K_selection.GetSize(); ++simd_i) {
          if (global_input_1K_selection[simd_i])
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_a[simd_i]);
          else
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_b[simd_i]);
        }
      }

      motion_parties.at(party_id)->Finish();
    };
    std::vector<std::thread> threads;
    for (auto& party : motion_parties) {
      const auto party_id = party->GetBackend()->GetConfiguration()->GetMyId();
      threads.emplace_back(std::bind(f, party_id));
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  }
}

TEST(BooleanGmw, Mux_1K_Simd_64_wireshare_2_3_parties) {
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(std::time(nullptr));
  for (auto number_of_parties : {2u, 3u}) {
    const std::size_t input1_owner = std::rand() % number_of_parties,
                      input2_owner = std::rand() % number_of_parties,
                      selection_bit_owner = std::rand() % number_of_parties,
                      output_owner = std::rand() % number_of_parties;

    std::vector<encrypto::motion::BitVector<>> global_input_1K_a(
        64, encrypto::motion::BitVector<>::SecureRandom(1000)),
        global_input_1K_b(64, encrypto::motion::BitVector<>::SecureRandom(1000));
    encrypto::motion::BitVector<> global_input_1K_selection{
        encrypto::motion::BitVector<>::SecureRandom(1000)};

    std::vector<encrypto::motion::BitVector<>> dummy_input_1K(64,
                                                              encrypto::motion::BitVector<>(1000));
    encrypto::motion::BitVector<> dummy_input_1K_sel(1000, false);
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }

    auto f = [&](std::size_t party_id) {
      encrypto::motion::ShareWrapper share_input_1K_a =
          party_id == input1_owner
              ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K_a, input1_owner)
              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K, input1_owner);
      encrypto::motion::ShareWrapper share_input_1K_b =
          party_id == input2_owner
              ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K_b, input2_owner)
              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K, input2_owner);
      encrypto::motion::ShareWrapper share_input_1K_selection =
          party_id == selection_bit_owner ? motion_parties.at(party_id)->In<kBooleanGmw>(
                                                global_input_1K_selection, selection_bit_owner)
                                          : motion_parties.at(party_id)->In<kBooleanGmw>(
                                                dummy_input_1K_sel, selection_bit_owner);

      auto share_selected = share_input_1K_selection.Mux(share_input_1K_a, share_input_1K_b);

      auto share_output_1K_all = share_selected.Out();

      motion_parties.at(party_id)->Run();

      for (auto i = 0; i < 64; ++i) {
        auto wire_1K = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
            share_output_1K_all->GetWires().at(i));

        assert(wire_1K);

        for (auto simd_i = 0ull; simd_i < global_input_1K_selection.GetSize(); ++simd_i) {
          if (global_input_1K_selection[simd_i])
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_a.at(i)[simd_i]);
          else
            EXPECT_EQ(wire_1K->GetValues()[simd_i], global_input_1K_b.at(i)[simd_i]);
        }
      }

      motion_parties.at(party_id)->Finish();
    };
    std::vector<std::thread> threads;
    for (auto& party : motion_parties) {
      const auto party_id = party->GetBackend()->GetConfiguration()->GetMyId();
      threads.emplace_back(std::bind(f, party_id));
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  }
}

TEST(BooleanGmw, Eq_1_bit_1K_Simd_2_3_parties) {
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(0);
  constexpr std::size_t kNumberOfSimd{1000}, kNumberOfWires{1};
  for (auto number_of_parties : {2u, 3u}) {
    std::size_t input_owner0 = std::rand() % number_of_parties, input_owner1 = input_owner0;
    while (input_owner0 == input_owner1) input_owner1 = std::rand() % number_of_parties;
    const std::size_t output_owner{std::rand() % number_of_parties};
    std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(number_of_parties);
    for (auto& bv_v : global_input) {
      bv_v.resize(kNumberOfWires);
      for (auto& bv : bv_v) {
        bv = encrypto::motion::BitVector<>::SecureRandom(kNumberOfSimd);
      }
    }
    std::vector<encrypto::motion::BitVector<>> dummy_input(
        kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

    std::vector<PartyPointer> motion_parties(
        MakeLocallyConnectedParties(number_of_parties, kPortOffset));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([kNumberOfSimd, kNumberOfWires, party_id, input_owner0, input_owner1,
                            &motion_parties, this, output_owner, &global_input, &dummy_input]() {
        std::vector<encrypto::motion::ShareWrapper> share_input;

        for (const auto input_owner : {input_owner0, input_owner1}) {
          if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            share_input.push_back(motion_parties.at(party_id)->In<kBooleanGmw>(
                global_input.at(input_owner), input_owner));
          } else {
            share_input.push_back(
                motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, input_owner));
          }
        }

        auto share_eq = (share_input.at(0) == share_input.at(1));

        auto share_output = share_eq.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto j = 0ull; j < share_output->GetWires().size(); ++j) {
            auto wire_single =
                std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                    share_output->GetWires().at(j));
            assert(wire_single);

            std::vector<encrypto::motion::BitVector<>> eq_check_v(kNumberOfWires);
            for (auto wire_i = 0ull; wire_i < kNumberOfWires; ++wire_i) {
              for (auto simd_i = 0ull; simd_i < kNumberOfSimd; ++simd_i) {
                eq_check_v.at(wire_i).Append(global_input.at(input_owner0).at(wire_i)[simd_i] ==
                                             global_input.at(input_owner1).at(wire_i)[simd_i]);
              }
            }

            auto eq_check = eq_check_v.at(0);
            for (auto wire_i = 1ull; wire_i < kNumberOfWires; ++wire_i)
              eq_check &= eq_check_v.at(wire_i);

            EXPECT_EQ(wire_single->GetValues(), eq_check);
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  }
}

TEST(BooleanGmw, Eq_64_bit_10_Simd_2_3_parties) {
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(0);
  constexpr std::size_t kNumberOfSimd{10}, kNumberOfWires{64};
  for (auto number_of_parties : {2u, 3u}) {
    std::size_t input_owner0 = std::rand() % number_of_parties, input_owner1 = input_owner0;
    while (input_owner0 == input_owner1) input_owner1 = std::rand() % number_of_parties;
    const std::size_t output_owner{std::rand() % number_of_parties};
    std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(number_of_parties);
    for (auto& bv_v : global_input) {
      bv_v.resize(kNumberOfWires);
      for (auto& bv : bv_v) {
        bv = encrypto::motion::BitVector<>::SecureRandom(kNumberOfSimd);
      }
    }

    // to guarantee that at least one EQ result is true
    global_input.at(0).at(0).Set(true);
    global_input.at(1).at(0).Set(true);

    std::vector<encrypto::motion::BitVector<>> dummy_input(
        kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

    std::vector<PartyPointer> motion_parties(
        MakeLocallyConnectedParties(number_of_parties, kPortOffset));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, input_owner0, input_owner1, &motion_parties, this,
                            output_owner, &global_input, &dummy_input]() {
        std::vector<encrypto::motion::ShareWrapper> share_input;

        for (const auto input_owner : {input_owner0, input_owner1}) {
          if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
            share_input.push_back(motion_parties.at(party_id)->In<kBooleanGmw>(
                global_input.at(input_owner), input_owner));
          } else {
            share_input.push_back(
                motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, input_owner));
          }
        }

        auto share_eq = (share_input.at(0) == share_input.at(1));

        auto share_output = share_eq.Out(output_owner);

        motion_parties.at(party_id)->Run();

        if (party_id == output_owner) {
          for (auto j = 0ull; j < share_output->GetWires().size(); ++j) {
            auto wire_single =
                std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                    share_output->GetWires().at(j));
            assert(wire_single);

            std::vector<encrypto::motion::BitVector<>> eq_check_v(kNumberOfWires);
            for (auto wire_i = 0ull; wire_i < kNumberOfWires; ++wire_i) {
              for (auto simd_i = 0ull; simd_i < kNumberOfSimd; ++simd_i) {
                eq_check_v.at(wire_i).Append(global_input.at(input_owner0).at(wire_i)[simd_i] ==
                                             global_input.at(input_owner1).at(wire_i)[simd_i]);
              }
            }

            auto eq_check = eq_check_v.at(0);
            for (auto wire_i = 1ull; wire_i < kNumberOfWires; ++wire_i)
              eq_check &= eq_check_v.at(wire_i);

            EXPECT_EQ(wire_single->GetValues(), eq_check);
          }
        }
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  }
}

TEST(BooleanGmw, And_1_bit_1_1K_Simd_2_3_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));
    for (auto number_of_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<bool> global_input_1(number_of_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<encrypto::motion::BitVector<>> global_input_1K(number_of_parties);

      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = encrypto::motion::BitVector<>::SecureRandom(1000);
      }
      bool dummy_input_1 = false;
      encrypto::motion::BitVector<> dummy_input_1K(1000, false);
      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }

        auto f = [&](std::size_t party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input_1, share_input_1K;

          for (auto j = 0ull; j < number_of_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              share_input_1.push_back(motion_parties.at(party_id)->In<kBooleanGmw>(
                  static_cast<bool>(global_input_1.at(j)), j));
              share_input_1K.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K.at(j), j));
            } else {
              share_input_1.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1, j));
              share_input_1K.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K, j));
            }
          }

          auto share_and_1 = share_input_1.at(0) & share_input_1.at(1);
          auto share_and_1K = share_input_1K.at(0) & share_input_1K.at(1);

          for (auto j = 2ull; j < number_of_parties; ++j) {
            share_and_1 = share_and_1 & share_input_1.at(j);
            share_and_1K = share_and_1K & share_input_1K.at(j);
          }

          auto share_output_1 = share_and_1.Out(output_owner);
          auto share_output_1K = share_and_1K.Out(output_owner);

          auto share_output_1_all = share_and_1.Out();
          auto share_output_1K_all = share_and_1K.Out();

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      encrypto::motion::BitVector<>::AndReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(),
                      encrypto::motion::BitVector<>::AndBitVectors(global_input_1K));
          }

          {
            auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1_all->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1K_all->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      encrypto::motion::BitVector<>::AndReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(),
                      encrypto::motion::BitVector<>::AndBitVectors(global_input_1K));
          }
        };

#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          f(party_id);
          // check multiplication triples
          if (party_id == 0) {
            encrypto::motion::BitVector<> a, b, c;
            a = motion_parties.at(0)->GetBackend()->GetMtProvider().GetBinaryAll().a;
            b = motion_parties.at(0)->GetBackend()->GetMtProvider().GetBinaryAll().b;
            c = motion_parties.at(0)->GetBackend()->GetMtProvider().GetBinaryAll().c;

            for (auto j = 1ull; j < motion_parties.size(); ++j) {
              a ^= motion_parties.at(j)->GetBackend()->GetMtProvider().GetBinaryAll().a;
              b ^= motion_parties.at(j)->GetBackend()->GetMtProvider().GetBinaryAll().b;
              c ^= motion_parties.at(j)->GetBackend()->GetMtProvider().GetBinaryAll().c;
            }
            EXPECT_EQ(c, a & b);
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGmw, And_64_bit_10_Simd_2_3_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));
    for (auto number_of_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<std::vector<encrypto::motion::BitVector<>>> global_input_10_64_bit(
          number_of_parties);
      for (auto& bv_v : global_input_10_64_bit) {
        bv_v.resize(64);
        for (auto& bv : bv_v) {
          bv = encrypto::motion::BitVector<>::SecureRandom(10);
        }
      }
      std::vector<encrypto::motion::BitVector<>> dummy_input_10_64_bit(
          64, encrypto::motion::BitVector<>(10, false));

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input;

          for (auto j = 0ull; j < number_of_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              share_input.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(global_input_10_64_bit.at(j), j));
            } else {
              share_input.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_10_64_bit, j));
            }
          }

          auto share_and = share_input.at(0) & share_input.at(1);

          for (auto j = 2ull; j < number_of_parties; ++j) {
            share_and = share_and & share_input.at(j);
          }

          auto share_output = share_and.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_10_64_bit.size(); ++j) {
              auto wire_single =
                  std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                      share_output->GetWires().at(j));
              assert(wire_single);

              std::vector<encrypto::motion::BitVector<>> global_input_single;
              for (auto k = 0ull; k < number_of_parties; ++k) {
                global_input_single.push_back(global_input_10_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_single->GetValues(),
                        encrypto::motion::BitVector<>::AndBitVectors(global_input_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGmw, Or_1_bit_1_1K_Simd_2_3_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));
    for (auto number_of_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<bool> global_input_1(number_of_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<encrypto::motion::BitVector<>> global_input_1K(number_of_parties);

      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = encrypto::motion::BitVector<>::SecureRandom(1000);
      }
      bool dummy_input_1 = false;
      encrypto::motion::BitVector<> dummy_input_1K(1000, false);
      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }

        auto f = [&](std::size_t party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input_1, share_input_1K;

          for (auto j = 0ull; j < number_of_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              share_input_1.push_back(motion_parties.at(party_id)->In<kBooleanGmw>(
                  static_cast<bool>(global_input_1.at(j)), j));
              share_input_1K.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K.at(j), j));
            } else {
              share_input_1.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1, j));
              share_input_1K.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K, j));
            }
          }

          auto share_or_1 = share_input_1.at(0) | share_input_1.at(1);
          auto share_or_1K = share_input_1K.at(0) | share_input_1K.at(1);

          for (auto j = 2ull; j < number_of_parties; ++j) {
            share_or_1 = share_or_1 | share_input_1.at(j);
            share_or_1K = share_or_1K | share_input_1K.at(j);
          }

          auto share_output_1_all = share_or_1.Out();
          auto share_output_1K_all = share_or_1K.Out();

          motion_parties.at(party_id)->Run();

          {
            auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1_all->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1K_all->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      encrypto::motion::BitVector<>::OrReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(),
                      encrypto::motion::BitVector<>::OrBitVectors(global_input_1K));
          }
          motion_parties.at(party_id)->Finish();
        };

#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          f(party_id);
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGmw, Or_64_bit_10_Simd_2_3_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));
    for (auto number_of_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<std::vector<encrypto::motion::BitVector<>>> global_input_10_64_bit(
          number_of_parties);
      for (auto& bv_v : global_input_10_64_bit) {
        bv_v.resize(64);
        for (auto& bv : bv_v) {
          bv = encrypto::motion::BitVector<>::SecureRandom(10);
        }
      }
      std::vector<encrypto::motion::BitVector<>> dummy_input_10_64_bit(
          64, encrypto::motion::BitVector<>(10, false));

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input;

          for (auto j = 0ull; j < number_of_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              share_input.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(global_input_10_64_bit.at(j), j));
            } else {
              share_input.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_10_64_bit, j));
            }
          }

          auto share_or = share_input.at(0) | share_input.at(1);

          for (auto j = 2ull; j < number_of_parties; ++j) {
            share_or = share_or | share_input.at(j);
          }

          auto share_output = share_or.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_10_64_bit.size(); ++j) {
              auto wire_single =
                  std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                      share_output->GetWires().at(j));
              assert(wire_single);

              std::vector<encrypto::motion::BitVector<>> global_input_single;
              for (auto k = 0ull; k < number_of_parties; ++k) {
                global_input_single.push_back(global_input_10_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_single->GetValues(),
                        encrypto::motion::BitVector<>::OrBitVectors(global_input_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}



class PartyGenerator {
 protected:
  void GenerateParties(bool online_after_setup) {
    parties_ = std::move(MakeLocallyConnectedParties(2, kPortOffset));
    for (auto& party : parties_) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(online_after_setup);
    }
  }

  std::vector<encrypto::motion::PartyPointer> parties_;
};

class SeededRandomnessGenerator {
 public:
  SeededRandomnessGenerator() = default;
  SeededRandomnessGenerator(std::size_t seed) { random_.seed(seed); }

 protected:
  BitVector<> RandomBits(std::size_t size) {
    std::bernoulli_distribution bool_dist;
    BitVector<> result;
    result.Reserve(size);
    while (result.GetSize() < size) result.Append(bool_dist(random_));
    return result;
  }

  bool RandomBit() {
    std::bernoulli_distribution bool_dist;
    return bool_dist(random_);
  }

  template <typename T>
  T RandomInteger() {
    static_assert(std::is_integral_v<T>, "T must be an integral type");
    std::uniform_int_distribution<T> value_dist;
    return value_dist(random_);
  }

  template <typename T>
  std::vector<T> RandomIntegers(std::size_t size) {
    static_assert(std::is_integral_v<T>, "T must be an integral type");
    std::uniform_int_distribution<T> value_dist;
    std::vector<T> result;
    result.reserve(size);
    while (result.size() < size) result.emplace_back(value_dist(random_));
    return result;
  }

  std::mt19937_64 random_{0};
};

template <typename T>
class TypedSignedBgmwTest : public testing::Test,
                            public PartyGenerator,
                            public SeededRandomnessGenerator {
 public:
  void SetUp() override {
    GenerateParties(false);
    GenerateRandomValues();
  }

 protected:
  void GenerateRandomValues() {
    values_a_ = RandomIntegers<T>(vector_size_);
    values_b_ = RandomIntegers<T>(vector_size_);
  }

  std::vector<T> values_a_, values_b_;
  std::size_t vector_size_{1000};
};

using SignedIntegerTypes = ::testing::Types<std::int8_t, std::int16_t, std::int32_t, std::int64_t>;
TYPED_TEST_SUITE(TypedSignedBgmwTest, SignedIntegerTypes);

TYPED_TEST(TypedSignedBgmwTest, SignedSubtraction_1K_Simd_2_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::vector<std::future<void>> futures;

  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures.push_back(std::async(std::launch::async, [this, party_id]() {
      encrypto::motion::SecureSignedInteger share_values_a_, share_values_b_;
      // If my input - real input, otherwise a dummy 0 (-vector).
      // Should not make any difference, just for consistency...
      std::vector<TypeParam> selected_values_a_ =
          party_id == 0 ? this->values_a_ : std::vector<TypeParam>(this->values_a_.size(), 0);
      std::vector<TypeParam> selected_values_b_ =
          party_id == 0 ? this->values_b_ : std::vector<TypeParam>(this->values_b_.size(), 0);

      share_values_a_ =
          this->parties_.at(party_id)->template In<encrypto::motion::MpcProtocol::kBooleanGmw>(
              ToInput(selected_values_a_), 0);
      share_values_b_ =
          this->parties_.at(party_id)->template In<encrypto::motion::MpcProtocol::kBooleanGmw>(
              ToInput(selected_values_b_), 0);

      auto share_sub = share_values_a_ - share_values_b_;

      auto share_output = share_sub.Out();

      this->parties_.at(party_id)->Run();

      auto circuit_result = share_output.As<std::vector<TypeParam>>();
      std::vector<TypeParam> expected_result;
      expected_result.reserve(circuit_result.size());
      for (std::size_t i = 0; i < this->values_a_.size(); ++i) {
        expected_result.emplace_back(this->values_a_[i] - this->values_b_[i]);
      }
      EXPECT_EQ(circuit_result, expected_result);

      this->parties_.at(party_id)->Finish();
    }));
  }
  for (auto& future : futures) future.get();
}

}