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
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"
#include "test_helpers.h"

using namespace encrypto::motion;

// //
// =================================================================================================
// Boolean GMW tests

// test passed
TEST(BooleanGmw, XCOTMul_1K_Simd_2_3_parties) {
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(std::time(nullptr));
  for (auto number_of_parties : {2u}) {
    const std::size_t input1_owner = std::rand() % number_of_parties,
                      selection_bit_owner = std::rand() % number_of_parties,
                      output_owner = std::rand() % number_of_parties;

    encrypto::motion::BitVector<> global_input_1K_a{
        encrypto::motion::BitVector<>::SecureRandom(1000)},
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
      encrypto::motion::ShareWrapper share_input_1K_selection =
          party_id == selection_bit_owner
              ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input_1K_selection,
                                                             selection_bit_owner)
              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input_1K,
              selection_bit_owner);

      auto share_selected = share_input_1K_selection.XCOTMul(share_input_1K_a);

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
            EXPECT_EQ(wire_1K->GetValues()[simd_i], false);
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

// test passed
TEST(BooleanGmw, XCOTMul_1K_Simd_64_wireshare_2_3_parties) {
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(std::time(nullptr));
  for (auto number_of_parties : {2u, 3u}) {
    const std::size_t input1_owner = std::rand() % number_of_parties,
                      selection_bit_owner = std::rand() % number_of_parties,
                      output_owner = std::rand() % number_of_parties;

    std::vector<encrypto::motion::BitVector<>> global_input_1K_a(
        64, encrypto::motion::BitVector<>::SecureRandom(1000));
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
      encrypto::motion::ShareWrapper share_input_1K_selection =
          party_id == selection_bit_owner ? motion_parties.at(party_id)->In<kBooleanGmw>(
                                                global_input_1K_selection, selection_bit_owner)
                                          : motion_parties.at(party_id)->In<kBooleanGmw>(
                                                dummy_input_1K_sel, selection_bit_owner);

      auto share_selected = share_input_1K_selection.XCOTMul(share_input_1K_a);

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
            EXPECT_EQ(wire_1K->GetValues()[simd_i], false);
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

// // test passed
// //
// =================================================================================================
// BMR tests

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

TEST_P(BmrHeavyTest, XCOTMul) {
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::srand(0);
  const std::size_t input1_owner = std::rand() % this->number_of_parties_,
                    // input2_owner = std::rand() % this->number_of_parties_,
      selection_bit_owner = std::rand() % this->number_of_parties_,
                    output_owner = std::rand() % this->number_of_parties_;
  std::vector<encrypto::motion::BitVector<>> global_input1(this->number_of_wires_),
      global_input2(this->number_of_wires_);
  for (auto& bv : global_input1)
    bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
  for (auto& bv : global_input2)
    bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
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
    threads.emplace_back([party_id, &motion_parties, this, input1_owner, selection_bit_owner,
                          output_owner, &global_input1, &global_input2, &bit_vector_selection,
                          &dummy_input, &dummy_selection]() {
      const auto my_id = motion_parties.at(party_id)->GetConfiguration()->GetMyId();
      SharePointer share_input1;
      if (input1_owner == my_id) {
        share_input1 = motion_parties.at(party_id)->In<kBmr>(global_input1, input1_owner);
      } else {
        share_input1 = motion_parties.at(party_id)->In<kBmr>(dummy_input, input1_owner);
      }

      // SharePointer share_input2;
      // if (input2_owner == my_id) {
      //   share_input2 = motion_parties.at(party_id)->In<kBmr>(global_input2, input2_owner);
      // } else {
      //   share_input2 = motion_parties.at(party_id)->In<kBmr>(dummy_input, input2_owner);
      // }

      SharePointer share_selection;
      if (selection_bit_owner == my_id) {
        share_selection =
            motion_parties.at(party_id)->In<kBmr>(bit_vector_selection, selection_bit_owner);
      } else {
        share_selection =
            motion_parties.at(party_id)->In<kBmr>(dummy_selection, selection_bit_owner);
      }

      encrypto::motion::ShareWrapper sw_in1(share_input1), sw_sel(share_selection);

      // sw_sel * sw_in_1
      auto sw_res = sw_sel.XCOTMul(sw_in1);

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
              EXPECT_EQ(wire_single->GetPublicValues()[j], false);
          }
        }
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
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

// ==============================================================
// test passed
// Garbled Circuit Test

// number of wires, SIMD values, and online-after-setup flag
using ParametersTypeGC = std::tuple<std::size_t, std::size_t, bool>;

class GarbledCircuitTest : public testing::TestWithParam<ParametersTypeGC> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_wires_, number_of_simd_, online_after_setup_) = parameters;

    parties_ = MakeParties();
    for (auto& party : parties_) {
      // XXX
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetLogger()->SetEnabled(true);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }

    global_inputs_.resize(2);
    for (auto& bv_v : global_inputs_) {
      bv_v.resize(number_of_wires_);
      for (auto& bv : bv_v) bv = GenerateRandomBitVector(number_of_simd_);
    }
  }

  void TearDown() override { number_of_wires_ = number_of_simd_ = 0; }

  std::vector<encrypto::motion::PartyPointer> MakeParties() {
    return encrypto::motion::MakeLocallyConnectedParties(2, kPortOffset);
  }

  encrypto::motion::BitVector<> GenerateRandomBitVector(std::size_t bitlength) {
    return encrypto::motion::BitVector<>::RandomSeeded(this->number_of_simd_,
                                                       this->bitvector_randomness_seed_++);
  }

 protected:
  std::size_t number_of_wires_ = 0, number_of_simd_ = 0;
  bool online_after_setup_ = false;
  std::vector<encrypto::motion::PartyPointer> parties_;
  std::size_t bitvector_randomness_seed_ = 0;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_inputs_;
  static constexpr auto garbler_id_{
      static_cast<std::size_t>(encrypto::motion::GarbledCircuitRole::kGarbler)};
  static constexpr std::size_t evaluator_id_{1 - garbler_id_};
};

TEST_P(GarbledCircuitTest, XCOTMul) {
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      auto [input_share_0, input_promise_0] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              0, 1, this->number_of_simd_);
      encrypto::motion::ShareWrapper input_0(input_share_0);

      // evaluator's input
      auto [input_share_1, input_promise_1] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              1, this->number_of_wires_, this->number_of_simd_);
      encrypto::motion::ShareWrapper input_1(input_share_1);

      std::vector<encrypto::motion::BitVector<>> choice_bits;

      // Set inputs using the obtained promises
      if (party_id == 0) {
        choice_bits.resize(1);
        choice_bits[0] = GenerateRandomBitVector(number_of_simd_);
        input_promise_0->set_value(choice_bits);
        // std::cout << "party 0: " << choice_bits[0] << std::endl;
        // std::cout << std::endl;
      } else {  // party_id == 1
        input_promise_1->set_value(this->global_inputs_[1]);
        // std::cout << "party 1: " << std::endl;
        // for (std::size_t i = 0; i < this->number_of_wires_; ++i) {
        //   std::cout << global_inputs_[1][i] << std::endl;
        // }
        // std::cout << std::endl;  
      }

      auto result{input_0.XCOTMul(input_1)};

      auto output{result.Out()};

      this->parties_[party_id]->Run();
      this->parties_[party_id]->Finish();

      if (party_id == 0) {
        // for (auto j = 0ull; j < number_of_simd_; ++j) {
        //   std::cout << "j: " << j << std::endl;
        //   std::cout << "choice_bits[0][j]: " << choice_bits[0][j] << std::endl;
        // }
        for (std::size_t i = 0; i < this->number_of_wires_; ++i) {
          // std::cout << "output: " << std::endl;
          // std::cout << "i: " << i << std::endl;
          // std::cout << output.GetWire(i).As<encrypto::motion::BitVector<>>() << std::endl;
          // std::cout << std::endl;

          for (auto j = 0ull; j < number_of_simd_; ++j) {
            // std::cout << "j: " << j << std::endl;
            // std::cout << "choice_bits[0][j]: " << choice_bits[0][j] << std::endl;
            if (choice_bits[0][j]) {
              EXPECT_EQ(output.GetWire(i).As<encrypto::motion::BitVector<>>()[j],
                        this->global_inputs_[1][i][j]);
            } else {
              EXPECT_EQ(output.GetWire(i).As<encrypto::motion::BitVector<>>()[j], false);
            }
          }
        }
      }
    }));
  }
  for (auto& f : futures) f.get();
}

constexpr std::array<std::size_t, 3> kGarbledCircuitNumberOfWires{1, 64, 100};
constexpr std::array<std::size_t, 3> kGarbledCircuitNumberOfSimd{1, 64, 100};
constexpr std::array<bool, 2> kGarbledCircuitOnlineAfterSetup{false, true};

INSTANTIATE_TEST_SUITE_P(GarbledCircuitTestSuite, GarbledCircuitTest,
                         testing::Combine(testing::ValuesIn(kGarbledCircuitNumberOfWires),
                                          testing::ValuesIn(kGarbledCircuitNumberOfSimd),
                                          testing::ValuesIn(kGarbledCircuitOnlineAfterSetup)),
                         [](const testing::TestParamInfo<GarbledCircuitTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<2>(info.param)) ? "Seq" : "Par";
                           std::string name =
                               fmt::format("{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                                           std::get<1>(info.param), mode);
                           return name;
                         });