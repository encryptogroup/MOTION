// MIT License
//
// Copyright (c) 2022 Liang Zhao
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
#include <bitset>
#include "base/party.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_dp_mechanism_helper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_constants.h"
#include "test_helpers.h"

using namespace encrypto::motion;

TEST(BooleanGmw, InvertBinaryTree_test2_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable1) {
    using T = decltype(template_variable1);
    std::size_t num_of_leaf = std::rand() % (sizeof(T) * 8);
    if (num_of_leaf == 0) {
      num_of_leaf++;
    }

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<T> input_y = ::RandomVector<T>(num_of_leaf);
      std::vector<bool> input_c = ::RandomBoolVector(num_of_leaf);

      // compute expect result
      T expected_result = 0;
      for (std::size_t i = 0; i < num_of_leaf; i++) {
        if (input_c[i] == 1) {
          expected_result = input_y[i];
          break;
        }
      }

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
          std::vector<encrypto::motion::ShareWrapper> share_input_y_vector;
          std::vector<encrypto::motion::ShareWrapper> share_input_c_vector;

          for (auto j = 0u; j < number_of_parties; ++j) {
            for (auto i = 0u; i < num_of_leaf; ++i) {
              const T my_input_y = party_id == 0 ? input_y.at(i) : 0;
              const bool my_input_c = party_id == 0 ? input_c.at(i) : 0;
              share_input_y_vector.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(my_input_y), 0));
              share_input_c_vector.push_back(
                  motion_parties.at(party_id)->In<kBooleanGmw>(BitVector<>(1, my_input_c), 0));
            }
          }
          std::vector<encrypto::motion::ShareWrapper> boolean_gmw_share_leaf_chosen =
              SecureDPMechanismHelper(share_input_y_vector[0])
                  .InvertBinaryTreeSelection(share_input_y_vector, share_input_c_vector);

          encrypto::motion::ShareWrapper boolean_gmw_share_leaf_chosen_y =
              boolean_gmw_share_leaf_chosen[0];
          encrypto::motion::ShareWrapper boolean_gmw_share_leaf_chosen_c =
              boolean_gmw_share_leaf_chosen[1];

          encrypto::motion::SecureUnsignedInteger boolean_gmw_share_leaf_chosen_y_out =
              boolean_gmw_share_leaf_chosen[0].Out();
          encrypto::motion::ShareWrapper boolean_gmw_share_leaf_chosen_c_out =
              boolean_gmw_share_leaf_chosen[1].Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            EXPECT_EQ(expected_result, boolean_gmw_share_leaf_chosen_y_out.As<T>());
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}
