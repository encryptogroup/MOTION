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
#include "cmath"
#include "protocols/arithmetic_gmw/arithmetic_gmw_gate.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/print_uint128_t.h"

using namespace encrypto::motion;

// auto random_value = std::mt19937{};

// test passed
TEST(BooleanGmw, edaBit_10_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable) {
    using T = decltype(template_variable);
    // const std::vector<T> kZeroV_1K(1000, 0);
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<T> input_1 = ::RandomVector<T>(number_of_parties);

      // number of edaBits
      std::size_t bit_size = std::mt19937{}() % (sizeof(T) * 8);
      // std::cout << "bit size: " << bit_size << std::endl;
      std::size_t num_of_simd = 10;

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input_1, share_input_1K;

          // parties secret share inputs
          for (auto j = 0u; j < number_of_parties; ++j) {
            const T my_input_1 = party_id == j ? input_1.at(j) : 0;

            share_input_1.push_back(
                motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(my_input_1), j));
          }

          // motion_parties.at(party_id)->In<kArithmeticConstant>(const_input_1);

          // auto edaBit_Gate = std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(
          //     share_input_1[0]->GetBackend(), bit_size, num_of_simd);
          // share_input_1[0]->GetRegister()->RegisterNextGate(edaBit_Gate);

          auto edaBit_Gate =
              share_input_1[0]->GetRegister()->EmplaceGate<proto::arithmetic_gmw::edaBitGate<T>>(
                  share_input_1[0]->GetBackend(), bit_size, num_of_simd);

          ShareWrapper boolean_gmw_share_r =
              std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
          ShareWrapper arithmetic_gmw_share_r =
              std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

          std::vector<encrypto::motion::SharePointer> arithmetic_gmw_share_r_of_each_bit_vector =
              (edaBit_Gate->GetOutputAsArithmeticShareOfEachBit());

          auto boolean_gmw_share_output_1 = boolean_gmw_share_r.Out(output_owner);
          auto arithmetic_gmw_share_output_1 = arithmetic_gmw_share_r.Out(output_owner);

          std::vector<ShareWrapper> arithmetic_gmw_share_r_of_each_bit_vector_out(bit_size);
          for (std::size_t i = 0; i < bit_size; i++) {
            arithmetic_gmw_share_r_of_each_bit_vector_out[i] =
                encrypto::motion::ShareWrapper(arithmetic_gmw_share_r_of_each_bit_vector[i])
                    .Out(output_owner);
          }

          // std::cout << "party run" << std::endl;

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            std::vector<T> arithmetic_gmw_share_output_1_as =
                arithmetic_gmw_share_output_1.As<std::vector<T>>();

            std::vector<BitVector<>> boolean_gmw_share_output_1_as_bitvector =
                boolean_gmw_share_output_1.As<std::vector<BitVector<>>>();

            std::vector<T> boolean_gmw_share_output_1_as_T =
                ToVectorOutput<T>(boolean_gmw_share_output_1_as_bitvector);

            for (std::size_t i = 0; i < num_of_simd; ++i) {
              // std::cout << "num_of_simd: " << i << std::endl;

              // std::cout << "arithmetic_gmw_share_output_1_as: ";
              // print_u128_u(arithmetic_gmw_share_output_1_as[i]);
              // std::cout << std::endl;

              // std::cout << "boolean_gmw_share_output_1_as_T: ";
              // print_u128_u(boolean_gmw_share_output_1_as_T[i]);
              // std::cout << std::endl;

              EXPECT_EQ(arithmetic_gmw_share_output_1_as[i], boolean_gmw_share_output_1_as_T[i]);

              for (std::size_t j = 0; j < bit_size; j++) {
                // std::cout<<"arithmetic_gmw_share_r_of_each_bit:
                // "<<arithmetic_gmw_share_r_of_each_bit << std::endl;
                bool arithmetic_gmw_share_r_of_each_bit =
                    arithmetic_gmw_share_r_of_each_bit_vector_out[j].As<std::vector<T>>()[i];
                // print_u128_u(
                // arithmetic_gmw_share_r_of_each_bit_vector_out[j].As<std::vector<T>>()[i]);

                // std::cout<<"boolean_gmw_share_output: "<<boolean_gmw_share_output << std::endl;
                bool boolean_gmw_share_output = boolean_gmw_share_output_1_as_bitvector[j][i];
                // std::cout << boolean_gmw_share_output << std::endl;
                EXPECT_EQ(arithmetic_gmw_share_r_of_each_bit, boolean_gmw_share_output);
              }
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
    template_test(static_cast<__uint128_t>(0));
  }
}
