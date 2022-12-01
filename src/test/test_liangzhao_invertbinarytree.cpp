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
#include <bitset>
#include "base/party.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_constants.h"
#include "test_helpers.h"

using namespace encrypto::motion;

// // test passed, remove elater
// TEST(BooleanGmw, InvertBinaryTree_test1_1_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable1) {
//     using T = decltype(template_variable1);
//     std::size_t num_of_leaf = std::rand() % (sizeof(T) * 8);
//     if (num_of_leaf == 0) {
//       num_of_leaf++;
//     }
//     // const std::vector<T> kZeroV_1K(1000, 0);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;
//       std::vector<T> input_1 = ::RandomVector<T>(num_of_leaf);

//       // compute expect result
//       T expected_result = 0;
//       for (std::size_t i = 0; i < num_of_leaf; i++) {
//         for (std::size_t bit_index = 0; bit_index < sizeof(T) * 8; bit_index++) {
//           if (std::bitset<sizeof(T) * 8>(input_1[i])[sizeof(T) * 8 - 1] == 1) {
//             expected_result = input_1[i];
//             goto end_loop;
//           }
//         }
//       }
//     end_loop:

//       try {
//         std::vector<PartyPointer> motion_parties(
//             std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
//         for (auto& party : motion_parties) {
//           party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//           party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
//         }
// #pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
// #pragma omp single
// #pragma omp taskloop num_tasks(motion_parties.size())
//         for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//           std::vector<encrypto::motion::ShareWrapper> share_input_1;

//           // parties secret share inputs
//           for (auto j = 0u; j < number_of_parties; ++j) {
//             // If my input - real input, otherwise a dummy 0 (-vector).
//             // Should not make any difference, just for consistency...

//             for (auto i = 0u; i < num_of_leaf; ++i) {
//               const T my_input_1 = party_id == 0 ? input_1.at(i) : 0;
//               share_input_1.push_back(
//                   motion_parties.at(party_id)->In<kBooleanGmw>(ToInput(my_input_1), 0));
//             }
//           }
//           encrypto::motion::ShareWrapper boolean_gmw_share_leaf_chosen =
//               share_input_1[0].InvertBinaryTreeSelection(share_input_1);

//           std::vector<encrypto::motion::ShareWrapper>
//               arithmetic_gmw_share_digit_decomposition_vector =
//                   arithmetic_gmw_share_digit_decomposition.Split();

//           std::cout << "arithmetic_gmw_share_digit_decomposition_vector.size: "
//                     << arithmetic_gmw_share_digit_decomposition_vector.size() << std::endl;

//           std::vector<encrypto::motion::ShareWrapper> boolean_gmw_share_leaf_chosen_vector =
//               boolean_gmw_share_leaf_chosen.Split();

//           std::vector<encrypto::motion::ShareWrapper> boolean_gmw_share_leaf_chosen_out_vector;

//           for (std::size_t i = 0; i < boolean_gmw_share_leaf_chosen_vector.size(); i++) {
//             boolean_gmw_share_leaf_chosen_out_vector.emplace_back(
//                 boolean_gmw_share_leaf_chosen_vector[i].Out());
//           }

//           std::cout << "party run" << std::endl;
//           motion_parties.at(party_id)->Run();
//           motion_parties.at(party_id)->Finish();
//           std::cout << "share_input_1_as: " << print_u128_u(share_input_1[0].As<T>()) <<
//           std::endl; for (std::size_t i = 2; i <
//           arithmetic_gmw_share_digit_decomposition_vector.size(); i++) {
//           std::cout<<"arithmetic_gmw_share_digit_decomposition_vector[i]: "<<"i= "<<i<<" "<<unsigned(arithmetic_gmw_share_digit_decomposition_vector[i].As<DigitType>())<<std::endl;          }

//           if (party_id == output_owner) {
//             std::cout << "expect result:" << unsigned(expected_result) << std::endl;
//             std::cout << "all result: " << std::endl;
//             for (std::size_t i = 0; i < num_of_leaf; i++) {
//               std::cout << unsigned(input_1[i]) << ": ";
//               std::cout << std::bitset<sizeof(T) * 8>(input_1[i]) << std::endl;
//             }
//             // std::cout << "input_1[0]: " << print_u128_u(input_1[0]) << std::endl;

//             // // calculate the expect MSNZB
//             // std::size_t output_bit_size = boolean_gmw_share_lookup_table_vector_out.size() -
//             // 1;
//             // std::size_t input_bit_size = sizeof(T) * 8;
//             // std::uint8_t value = input_1[0];
//             // unsigned MSNZB = 0;
//             // while (value >>= 1) {
//             //   MSNZB++;
//             // }
//             // MSNZB = input_bit_size - 1 - MSNZB;
//             // std::cout << "MSNZB: " << MSNZB << std::endl;
//             // std::vector<bool> MSNZB_binary_vector;
//             // for (std::size_t bit_index = 0; bit_index < output_bit_size; bit_index++) {
//             //   MSNZB_binary_vector.emplace_back(
//             //       MSNZB & (std::uint64_t(1) << (output_bit_size - 1 - bit_index)));
//             // }
//             // if (input_1[0] == 0) {
//             //   MSNZB_binary_vector.emplace_back(true);
//             // } else {
//             //   MSNZB_binary_vector.emplace_back(false);
//             // }

//             // std::cout << "MSNZB_binary_vector: ";
//             // for (std::size_t i = 0; i < MSNZB_binary_vector.size(); i++) {
//             //   bool output_bit_tmp = MSNZB_binary_vector[i];
//             //   std::cout << unsigned(output_bit_tmp);
//             // }
//             // std::cout << std::endl;

//             // #pragma omp barrier
//             // compute the computed digit
//             std::cout << "boolean_gmw_share_leaf_chosen_out_vector_as: ";
//             std::cout << std::endl;
//             for (std::size_t i = 0; i < boolean_gmw_share_leaf_chosen_out_vector.size(); i++) {
//               bool boolean_gmw_share_leaf_chosen_bit_out_as =
//                   boolean_gmw_share_leaf_chosen_out_vector[i].As<bool>();
//               // std::cout << boolean_gmw_share_leaf_chosen_bit_out_as;
//             }
//             std::cout << std::endl;

//             std::reverse(boolean_gmw_share_leaf_chosen_out_vector.begin(),
//                          boolean_gmw_share_leaf_chosen_out_vector.end());
//             for (std::size_t i = 0; i < boolean_gmw_share_leaf_chosen_out_vector.size(); i++) {
//               bool boolean_gmw_share_leaf_chosen_bit_out_as =
//                   boolean_gmw_share_leaf_chosen_out_vector[i].As<bool>();
//               std::cout << boolean_gmw_share_leaf_chosen_bit_out_as;
//             }
//             std::cout << std::endl;

//             //             // compute expect result
//             //             std::vector<DigitType> expect_digit_decomposition_vector;
//             // std::size_t number_of_digits = sizeof(T)/sizeof(DigitType);
//             // std::size_t digit_bit_size = sizeof(DigitType)*8;
//             //  T digit_mask = (T(1) << digit_bit_size) - 1;

//             // for (auto i = 0ull; i < number_of_digits; i++) {
//             //       expect_digit_decomposition_vector.emplace_back(
//             //           DigitType(input_1[0] >> i * digit_bit_size) & digit_mask);}
//             //
//             // std::reverse(expect_digit_decomposition_vector.begin(),expect_digit_decomposition_vector.end());

//             // // check the equality
//             for (std::size_t i = 0; i < boolean_gmw_share_leaf_chosen_out_vector.size(); i++) {
//               bool boolean_gmw_share_leaf_chosen_bit_out_as =
//                   boolean_gmw_share_leaf_chosen_out_vector[i].As<bool>();
//               bool expect_bit = std::bitset<sizeof(T) * 8>(expected_result)[i];

//               EXPECT_EQ(boolean_gmw_share_leaf_chosen_out_vector, expect_bit);
//             }
//           }
//         }
//       } catch (std::exception& e) {
//         std::cerr << e.what() << std::endl;
//       }
//     }
//   };
//   for (auto i = 0ull; i < kTestIterations; ++i) {
//     template_test(static_cast<std::uint8_t>(0));
//     template_test(static_cast<std::uint16_t>(0));
//     template_test(static_cast<std::uint32_t>(0));
//     template_test(static_cast<std::uint64_t>(0));
//   }
// }

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

      // // only for debug
      // for (std::size_t i = 0; i < num_of_leaf; i++) {
      //   input_c[i] = 0;
      // }

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

          // parties secret share inputs
          for (auto j = 0u; j < number_of_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...

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
              share_input_y_vector[0].InvertBinaryTreeSelection(share_input_y_vector,
                                                                share_input_c_vector);

          encrypto::motion::ShareWrapper boolean_gmw_share_leaf_chosen_y =
              boolean_gmw_share_leaf_chosen[0];
          encrypto::motion::ShareWrapper boolean_gmw_share_leaf_chosen_c =
              boolean_gmw_share_leaf_chosen[1];

          encrypto::motion::SecureUnsignedInteger boolean_gmw_share_leaf_chosen_y_out =
              boolean_gmw_share_leaf_chosen[0].Out();
          encrypto::motion::ShareWrapper boolean_gmw_share_leaf_chosen_c_out =
              boolean_gmw_share_leaf_chosen[1].Out();

          // std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          // std::cout << "share_input_1_as: " << print_u128_u(share_input_1[0].As<T>()) <<
          // std::endl; for (std::size_t i = 2; i <
          // arithmetic_gmw_share_digit_decomposition_vector.size(); i++) {
          // std::cout<<"arithmetic_gmw_share_digit_decomposition_vector[i]: "<<"i= "<<i<<"
          // "<<unsigned(arithmetic_gmw_share_digit_decomposition_vector[i].As<DigitType>())<<std::endl;
          // }

          if (party_id == output_owner) {
            // std::cout << "expect result:" << (expected_result) << std::endl;
            // std::cout << "input_y: " << std::endl;
            // for (std::size_t i = 0; i < num_of_leaf; i++) {
            //   std::cout << (input_y[i]) << ": ";
            //   std::cout << input_c[i] << std::endl;
            // }
            // std::cout << std::endl;

            // #pragma omp barrier
            // std::cout << "boolean_gmw_share_leaf_chosen_y_out: ";
            // std::cout << boolean_gmw_share_leaf_chosen_y_out.As<T>() << std::endl;
            // std::cout << "boolean_gmw_share_leaf_chosen_c_out: ";
            // std::cout << boolean_gmw_share_leaf_chosen_c_out.As<bool>() << std::endl;

            // // check the equality
            // for (std::size_t i = 0; i < boolean_gmw_share_leaf_chosen_out_vector.size(); i++) {
            //   bool boolean_gmw_share_leaf_chosen_bit_out_as =
            //       boolean_gmw_share_leaf_chosen_out_vector[i].As<bool>();
            //   bool expect_bit = std::bitset<sizeof(T) * 8>(expected_result)[i];

            EXPECT_EQ(expected_result, boolean_gmw_share_leaf_chosen_y_out.As<T>());
            // }
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
