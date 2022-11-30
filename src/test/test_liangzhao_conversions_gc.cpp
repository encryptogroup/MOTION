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

// added by Liang Zhao
#include "protocols/garbled_circuit/garbled_circuit_constants.h"
#include "protocols/garbled_circuit/garbled_circuit_gate.h"
#include "protocols/garbled_circuit/garbled_circuit_provider.h"
#include "protocols/garbled_circuit/garbled_circuit_share.h"
#include "protocols/garbled_circuit/garbled_circuit_wire.h"

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

// TEST_P(ConversionTest, Y2B) {
//   constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
//   std::srand(0);
//   const std::size_t input_owner = std::rand() % this->number_of_parties_,
//                     output_owner = std::rand() % this->number_of_parties_;
//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input(this->number_of_parties_);
//   for (auto& bv_v : global_input) {
//     bv_v.resize(this->number_of_wires_);
//     for (auto& bv : bv_v) {
//       bv = encrypto::motion::BitVector<>::SecureRandom(this->number_of_simd_);
//     }
//   }
//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       this->number_of_wires_, encrypto::motion::BitVector<>(this->number_of_simd_, false));

//   try {
//     std::vector<PartyPointer> motion_parties(
//         std::move(MakeLocallyConnectedParties(this->number_of_parties_, kPortOffset)));
//     for (auto& party : motion_parties) {
//       party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//       party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
//     }
//     std::vector<std::thread> threads;
//     for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//       threads.emplace_back([party_id, &motion_parties, this, input_owner, output_owner,
//                             &global_input, &dummy_input]() {
//         SharePointer temporary_share;
//         if (input_owner == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
//           temporary_share =
//               motion_parties.at(party_id)->In<kBmr>(global_input.at(input_owner), input_owner);
//         } else {
//           temporary_share = motion_parties.at(party_id)->In<kBmr>(dummy_input, input_owner);
//         }

//         encrypto::motion::ShareWrapper share_input(temporary_share);
//         EXPECT_EQ(share_input->GetBitLength(), this->number_of_wires_);
//         const auto share_conversion{share_input.Convert<MpcProtocol::kBooleanGmw>()};
//         auto share_output{share_conversion.Out(output_owner)};

//         motion_parties.at(party_id)->Run();

//         if (party_id == output_owner) {
//           for (auto i = 0ull; i < this->number_of_wires_; ++i) {
//             auto
//             wire_single{std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                 share_output->GetWires().at(i))};
//             assert(wire_single);
//             EXPECT_EQ(wire_single->GetValues(), global_input.at(input_owner).at(i));
//           }
//         }
//         motion_parties.at(party_id)->Finish();
//       });
//     }
//     for (auto& t : threads)
//       if (t.joinable()) t.join();
//   } catch (std::exception& e) {
//     std::cerr << e.what() << std::endl;
//   }
// }

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

        std::cout << "share_input.Convert<MpcProtocol::kGarbledCircuit>()" << std::endl;

        const auto share_conversion{share_input.Convert<MpcProtocol::kGarbledCircuit>()};
        auto share_output{share_conversion.Out(output_owner)};

        std::cout << "party run" << std::endl;
        motion_parties.at(party_id)->Run();
        std::cout << "party run finish" << std::endl;

        if (party_id == output_owner) {
          for (auto i = 0ull; i < this->number_of_wires_; ++i) {
            // auto
            // wire_single{std::dynamic_pointer_cast<encrypto::motion::proto::garbled_circuit::Wire>(
            //     share_output->GetWires().at(i))};
            // assert(wire_single);

            std::cout << "wire_single.As<encrypto::motion::BitVector<>>(): "
                      << share_output.GetWire(i).As<encrypto::motion::BitVector<>>() << std::endl;
            // EXPECT_EQ(wire_single->GetPublicValues(), global_input.at(input_owner).at(i));
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

constexpr std::array<std::size_t, 1> kConversionNumberOfParties{2};
// constexpr std::array<std::size_t, 3> kConversionNumberOfWires{1, 10, 64};
// constexpr std::array<std::size_t, 3> kConversionNumberOfSimd{1, 10, 64};
// constexpr std::array<bool, 2> kConversionOnlineAfterSetup{false, true};
constexpr std::array<std::size_t, 1> kConversionNumberOfWires{1};
constexpr std::array<std::size_t, 1> kConversionNumberOfSimd{1};
constexpr std::array<bool, 1> kConversionOnlineAfterSetup{false};

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

}  // namespace
