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


// TEST(ArithmeticGmw, EQ_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;

//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> input_2 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         std::cout << "edge_case==0" << std::endl;
//         input_2 = zero_vector;
//       } else if (edge_case == 1) {
//         std::cout << "edge_case==1" << std::endl;
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         std::cout << "edge_case==2" << std::endl;
//         input_2 = input_1;
//       } else if (edge_case == 3) {
//         std::cout << "edge_case==3" << std::endl;
//         input_2 = zero_vector;
//         input_1 = zero_vector;
//       }

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
//           std::vector<encrypto::motion::ShareWrapper> share_input_2;

//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
//             share_input_2.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_2, j));
//           }
//           auto share_compare =
//               share_input_1[0].EQ<T>(share_input_1[0], share_input_2[0], sizeof(T) * 8);

//           auto share_output_1 = share_compare.Out(output_owner);

//           // std::cout << "party run" << std::endl;
//           motion_parties.at(party_id)->Run();
//           motion_parties.at(party_id)->Finish();
//           // std::cout << "party finish" << std::endl;

//           if (party_id == output_owner) {
//             auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                 share_output_1->GetWires().at(0));
//             for (std::size_t i = 0; i < num_of_simd; i++) {
//               bool comparison_result_1 = wire_1->GetValues().Get(i);
//               bool expected_comparison_result_1 = input_1[i] == input_2[i];
//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
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
//     template_test(static_cast<__uint128_t>(0));  // should support now
//   }
// }


// TEST(ArithmeticGmw, EQC_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;

//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> input_2 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         input_2 = zero_vector;
//       } else if (edge_case == 1) {
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         input_2 = input_1;
//       } else if (edge_case == 3) {
//         input_2 = zero_vector;
//         input_1 = zero_vector;
//       }

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
//           std::vector<encrypto::motion::ShareWrapper> share_input_2;

//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
//             share_input_2.push_back(motion_parties.at(party_id)->In<kArithmeticConstant>(input_2));
//           }
//           auto share_compare =
//               share_input_1[0].EQC<T>(share_input_1[0], share_input_2[0], sizeof(T) * 8);

//           auto share_output_1 = share_compare.Out(output_owner);

//           // std::cout << "party run" << std::endl;
//           motion_parties.at(party_id)->Run();
//           motion_parties.at(party_id)->Finish();
//           // std::cout << "party finish" << std::endl;

//           if (party_id == output_owner) {
//             auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                 share_output_1->GetWires().at(0));
//             for (std::size_t i = 0; i < num_of_simd; i++) {
//               bool comparison_result_1 = wire_1->GetValues().Get(i);
//               bool expected_comparison_result_1 = input_1[i] == input_2[i];
//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
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
//     template_test(static_cast<__uint128_t>(0));  // should support now
//   }
// }


TEST(ArithmeticGmw, EQZ_10_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable) {
    using T = decltype(template_variable);
    // const std::vector<T> kZeroV_1K(1000, 0);
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = std::rand() % number_of_parties;

      std::size_t num_of_simd = 10;

      std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
      std::vector<T> input_2 = ::RandomVector<T>(num_of_simd);

      // test for edge case:
      // test for edge case:
      std::mt19937 mt(time(nullptr));
      std::size_t edge_case = mt() % 8;
      std::vector<T> zero_vector(num_of_simd, 0);
      if (edge_case == 0) {
        input_2 = zero_vector;
      } else if (edge_case == 1) {
        input_1 = zero_vector;
      } else if (edge_case == 2) {
        input_2 = input_1;
      } else if (edge_case == 3) {
        input_2 = zero_vector;
        input_1 = zero_vector;
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
          std::vector<encrypto::motion::ShareWrapper> share_input_1;
          std::vector<encrypto::motion::ShareWrapper> share_input_2;

          for (auto j = 0u; j < number_of_parties; ++j) {
            share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
            share_input_2.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_2, j));
          }
          auto share_compare =
              share_input_1[0].EQZ<T>(share_input_1[0] - share_input_2[0], sizeof(T) * 8);

          auto share_output_1 = share_compare.Out(output_owner);
          // auto share_output_1K = share_add_1K.Out(output_owner);

          // auto share_output_1_all = share_compare.Out();
          // auto share_output_1K_all = share_add_1K.Out();

          // std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          // std::cout << "party finish" << std::endl;

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                share_output_1->GetWires().at(0));
            for (std::size_t i = 0; i < num_of_simd; i++) {
              bool comparison_result_1 = wire_1->GetValues().Get(i);
              bool expected_comparison_result_1 = (input_1[i] == input_2[i]);
              EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));

    // should support now
    template_test(static_cast<__uint128_t>(0));
  }
}


// TEST(BooleanGmw, LTBits_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;
//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> const_input_1 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         const_input_1 = zero_vector;
//       } else if (edge_case == 1) {
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         const_input_1 = input_1;
//       } else if (edge_case == 3) {
//         const_input_1 = zero_vector;
//         input_1 = zero_vector;
//       }

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
//           std::vector<encrypto::motion::ShareWrapper> share_input_1, share_input_1K;

//           // parties secret share inputs
//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(
//                 motion_parties.at(party_id)->In<kBooleanGmw>(ToInput(input_1), j));
//           }

//           encrypto::motion::ShareWrapper share_const_input_1 =
//               motion_parties.at(party_id)->In<kArithmeticConstant>(const_input_1);

//           encrypto::motion::ShareWrapper share_compare =
//               share_input_1[0].LTBits(share_const_input_1, share_input_1[0]);

//           auto share_output_1 = share_compare.Out(output_owner);

//           motion_parties.at(party_id)->Run();

//           if (party_id == output_owner) {
//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               auto wire_1 =
//               std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                   share_output_1->GetWires().at(0));
//               bool comparison_result_1 = wire_1->GetValues().Get(i);
//               bool expected_comparison_result_1 = const_input_1[i] <= input_1[i];
//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
//             }
//           }
//           motion_parties.at(party_id)->Finish();
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
//     template_test(static_cast<__uint128_t>(0));
//   }
// }


// TEST(BooleanGmw, LTTBits_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;
//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> const_input_1 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         const_input_1 = zero_vector;
//       } else if (edge_case == 1) {
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         const_input_1 = input_1;
//       } else if (edge_case == 3) {
//         const_input_1 = zero_vector;
//         input_1 = zero_vector;
//       }

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
//           std::vector<encrypto::motion::ShareWrapper> share_input_1, share_input_1K;

//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(
//                 motion_parties.at(party_id)->In<kBooleanGmw>(ToInput(input_1), j));
//           }

//           encrypto::motion::ShareWrapper share_const_input_1 =
//               motion_parties.at(party_id)->In<kArithmeticConstant>(const_input_1);

//           encrypto::motion::ShareWrapper share_compare =
//               share_input_1[0].LTTBits(share_const_input_1, share_input_1[0]);

//           auto share_output_1 = share_compare.Out(output_owner);

//           motion_parties.at(party_id)->Run();

//           if (party_id == output_owner) {
//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               auto wire_1 =
//               std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                   share_output_1->GetWires().at(0));
//               bool comparison_result_1 = wire_1->GetValues().Get(i);
//               bool expected_comparison_result_1 = const_input_1[i] < input_1[i];
//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
//             }
//           }
//           motion_parties.at(party_id)->Finish();
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
//     template_test(static_cast<__uint128_t>(0));
//   }
// }


// TEST(BooleanGmw, LTC_MRVW_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     // const std::vector<T> kZeroV_1K(1000, 0);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;

//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> const_input_1 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         // std::cout << "case0" << std::endl;
//         const_input_1 = zero_vector;
//       } else if (edge_case == 1) {
//         // std::cout << "case1" << std::endl;
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         // std::cout << "case2" << std::endl;
//         const_input_1 = input_1;
//       }

//       // const_input_1 must be greater than zero
//       for (std::size_t i = 0; i < num_of_simd; ++i) {
//         if (const_input_1[i] == 0) {
//           const_input_1[i] = 1;
//         }
//       }

//       // // only for debugging
//       // for (std::size_t i = 0; i < input_1.size(); ++i) {
//         // std::cout<<"input_1: "<<input_1[i]<<std::endl;
//         // std::cout<<"const_input_1: "<<const_input_1[i]<<std::endl;
//         // print_u128_u_neg("input_1: ", input_1[i]);
//         // print_u128_u_neg("const_input_1: ", const_input_1[i]);

//         // const_input_1 = zero_vector;
//         // input_1 = zero_vector;
//       // }

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

//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
//           }

//           encrypto::motion::ShareWrapper share_const_input_1 =
//               motion_parties.at(party_id)->In<kArithmeticConstant>(const_input_1);

//           std::vector<encrypto::motion::ShareWrapper> share_compare =
//               share_input_1[0].LTC_MRVW<T>(share_input_1[0], share_const_input_1);
//           auto share_output_0 = share_compare[0].Out(output_owner);

//           // // only for debugging
//           // auto share_output_1 = share_compare[1].Out(output_owner);
//           // auto share_output_2 = share_compare[2].Out(output_owner);
//           // auto share_output_3 = share_compare[3].Out(output_owner);
//           // auto share_output_4 = share_compare[4].Out(output_owner);
//           // auto share_output_5 = share_compare[5].Out(output_owner);
//           // auto share_output_6 = share_compare[6].Out(output_owner);

//           // std::cout << "party run" << std::endl;
//           motion_parties.at(party_id)->Run();
//           motion_parties.at(party_id)->Finish();
//           // std::cout << "party finish" << std::endl;

//           if (party_id == output_owner) {
//             // auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//             //     share_output_1->GetWires().at(0));
//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               bool comparison_result_1 = share_output_0.As<BitVector<>>()[i];
//               bool expected_comparison_result_1 = input_1[i] < const_input_1[i];

//               // // only for debug
//               // std::cout << "arithmetic_gmw_share_r: " << int(share_output_1.As<std::vector<T>>()[i])
//               //           << std::endl;
//               // std::cout << "arithmetic_value_a: " << int(share_compare[2].As<std::vector<T>>()[i])
//               //           << std::endl;
//               // std::cout << "value_b: " << int(share_compare[3].As<std::vector<T>>()[i])
//               //           << std::endl;
//               // std::cout << "w_1: " << int(share_output_4.As<BitVector<>>()[i]) << std::endl;
//               // std::cout << "w_2: " << int(share_output_5.As<BitVector<>>()[i]) << std::endl;
//               // std::cout << "boolean_value_w3: " << int(share_output_6.As<BitVector<>>()[i])
//               //           << std::endl;

//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
//               // std::cout << std::endl;
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
//     template_test(static_cast<__uint128_t>(0));  // should support now
//   }
// }


// TEST(BooleanGmw, LTEQC_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;

//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> const_input_1 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         const_input_1 = zero_vector;
//       } else if (edge_case == 1) {
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         const_input_1 = input_1;
//       } else if (edge_case == 3) {
//         const_input_1 = zero_vector;
//         input_1 = zero_vector;
//       }

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

//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
//           }

//           encrypto::motion::ShareWrapper share_const_input_1 =
//               motion_parties.at(party_id)->In<kArithmeticConstant>(const_input_1);

//           encrypto::motion::ShareWrapper share_compare =
//               share_input_1[0].LTEQC<T>(share_input_1[0], share_const_input_1);

//           auto share_output_1 = share_compare.Out(output_owner);

//           motion_parties.at(party_id)->Run();

//           if (party_id == output_owner) {
//             auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                 share_output_1->GetWires().at(0));
//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               bool comparison_result_1 = wire_1->GetValues().Get(i);
//               bool expected_comparison_result_1 = input_1[i] <= const_input_1[i];
//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
//             }
//           }
//           motion_parties.at(party_id)->Finish();
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
//     template_test(static_cast<__uint128_t>(0));  // should support now
//   }
// }


// TEST(ArithmeticGmw, LTS_MRVW_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;

//       std::size_t num_of_simd = 10;
//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> input_2 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         std::cout << "case0" << std::endl;
//         input_2 = zero_vector;
//       } else if (edge_case == 1) {
//         std::cout << "case1" << std::endl;
//         // input_1 = zero_vector; // this case is not covered by the LTS_MRVW
//       } else if (edge_case == 2) {
//         std::cout << "case2" << std::endl;
//         input_2 = input_1;
//       } else if (edge_case == 3) {
//         std::cout << "case3" << std::endl;
//         // input_2 = zero_vector;  // this case is not covered by the LTS_MRVW
//         // input_1 = zero_vector;  // this case is not covered by the LTS_MRVW
//       }

//       // input_2 = zero_vector;
//       // input_1 = zero_vector;

//       // protocol doesn't cover this case (i.e., input_1[0] == 0)
//       for (std::size_t i = 0; i < input_1.size(); ++i) {
//         if (input_1[i] == 0) {
//           input_1[i] = input_1[i] + 1;
//         }
//       }

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
//           std::vector<encrypto::motion::ShareWrapper> share_input_2;

//           // parties secret share inputs
//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
//             share_input_2.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_2, j));
//           }
//           std::vector<ShareWrapper> result_vector =
//               share_input_1[0].LTS_MRVW<T>(share_input_1[0], share_input_2[0]);

//           ShareWrapper share_compare = result_vector[0];
//           // ShareWrapper arithmetic_value_a = result_vector[1];
//           // ShareWrapper arithmetic_value_b = result_vector[2];
//           // ShareWrapper arithmetic_value_T = result_vector[3];
//           // ShareWrapper boolean_gmw_share_w1 = result_vector[4];
//           // ShareWrapper boolean_gmw_share_w2 = result_vector[5];
//           // ShareWrapper boolean_value_w3 = result_vector[6];
//           // ShareWrapper boolean_gmw_share_w4 = result_vector[7];
//           // ShareWrapper boolean_gmw_share_w5 = result_vector[8];
//           // ShareWrapper arithmetic_gmw_share_r = result_vector[9];
//           // ShareWrapper arithmetic_gmw_share_r_prime = result_vector[10];

//           auto share_compare_out = share_compare.Out(output_owner);
//           // auto arithmetic_value_a_out = arithmetic_value_a.Out(output_owner);
//           // auto arithmetic_value_b_out = arithmetic_value_b.Out(output_owner);
//           // auto arithmetic_value_T_out = arithmetic_value_T.Out(output_owner);
//           // std::cout<<"11"<<std::endl;
//           // auto boolean_gmw_share_w1_out = boolean_gmw_share_w1.Out(output_owner);
//           // auto boolean_gmw_share_w2_out = boolean_gmw_share_w2.Out(output_owner);
//           // // auto boolean_value_w3_out = boolean_value_w3.Out(output_owner);
//           // auto boolean_gmw_share_w4_out = boolean_gmw_share_w4.Out(output_owner);
//           // auto boolean_gmw_share_w5_out = boolean_gmw_share_w5.Out(output_owner);
//           // // std::cout<<"22"<<std::endl;
//           // auto arithmetic_gmw_share_r_out = arithmetic_gmw_share_r.Out(output_owner);
//           // auto arithmetic_gmw_share_r_prime_out =
//           // arithmetic_gmw_share_r_prime.Out(output_owner);
//           // std::cout<<"33"<<std::endl;

//           // std::cout << "party run" << std::endl;
//           motion_parties.at(party_id)->Run();
//           motion_parties.at(party_id)->Finish();
//           // std::cout << "party finish" << std::endl;

//           if (party_id == output_owner) {
//             auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                 share_compare_out->GetWires().at(0));

//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               bool comparison_result_1 = wire_1->GetValues().Get(i);
//               bool expected_comparison_result_1 = T(input_1[i]) <= T(input_2[i]);
//               // std::cout << "x[0]: " << unsigned(input_1[0]) << std::endl;
//               // std::cout << "y[0]: " << unsigned(input_2[0]) << std::endl;

//               // std::cout << "share_compare_out: " << share_compare_out.As<bool>() << std::endl;
//               // std::cout << "arithmetic_value_a: " << unsigned(arithmetic_value_a.As<T>())
//               //           << std::endl;
//               // std::cout << "arithmetic_value_b: " << unsigned(arithmetic_value_b.As<T>())
//               //           << std::endl;
//               // std::cout << "arithmetic_value_T: " << unsigned(arithmetic_value_T.As<T>())
//               //           << std::endl;
//               // std::cout << "boolean_gmw_share_w1_out: " << boolean_gmw_share_w1_out.As<bool>()
//               //           << std::endl;
//               // std::cout << "boolean_gmw_share_w2_out: " << boolean_gmw_share_w2_out.As<bool>()
//               //           << std::endl;
//               // std::cout << "boolean_value_w3: " << boolean_value_w3.As<bool>() << std::endl;
//               // std::cout << "boolean_gmw_share_w4_out: " << boolean_gmw_share_w4_out.As<bool>()
//               //           << std::endl;
//               // std::cout << "boolean_gmw_share_w5_out: " << boolean_gmw_share_w5_out.As<bool>()
//               //           << std::endl;
//               // std::cout << "arithmetic_gmw_share_r_out: "
//               //           << unsigned(arithmetic_gmw_share_r_out.As<T>()) << std::endl;
//               // std::cout << "arithmetic_gmw_share_r_prime_out: "
//               //           << unsigned(arithmetic_gmw_share_r_prime_out.As<T>()) << std::endl;

//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
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
//     // not support yet, need to support boolean circuit (256-bit)
//     // template_test(static_cast<__uint128_t>(0));
//   }
// }


// TEST(ArithmeticGmw, LTEQS_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable) {
//     using T = decltype(template_variable);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;
//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> input_2 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         input_2 = zero_vector;
//       } else if (edge_case == 1) {
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         input_2 = input_1;
//       } else if (edge_case == 3) {
//         input_2 = zero_vector;
//         input_1 = zero_vector;
//       }

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
//           std::vector<encrypto::motion::ShareWrapper> share_input_2;

//           // parties secret share inputs
//           for (auto j = 0u; j < number_of_parties; ++j) {
//             share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
//             share_input_2.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_2, j));
//           }
//           ShareWrapper result_vector =
//               share_input_1[0].LTEQS<T>(share_input_1[0], share_input_2[0]);

//           ShareWrapper share_compare = result_vector;

//           auto share_compare_out = share_compare.Out(output_owner);

//           // std::cout << "party run" << std::endl;
//           motion_parties.at(party_id)->Run();
//           motion_parties.at(party_id)->Finish();
//           // std::cout << "party finish" << std::endl;

//           if (party_id == output_owner) {
//             auto wire_1 = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
//                 share_compare_out->GetWires().at(0));
//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               bool comparison_result_1 = wire_1->GetValues().Get(i);
//               bool expected_comparison_result_1 = T(input_1[i]) <= T(input_2[i]);
//               EXPECT_EQ(comparison_result_1, expected_comparison_result_1);
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
//     // not support yet, need to support boolean circuit (256-bit)
//     // template_test(static_cast<__uint128_t>(0));
//   }
// }


// TEST(ArithmeticGmw, LTZ_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable1, auto template_variable2) {
//     using T = decltype(template_variable1);
//     using T_int = decltype(template_variable2);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;
//       std::size_t num_of_simd = 10;
//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);

//       std::size_t test_case = std::mt19937{}() % 4;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (test_case == 0) {
//         input_1 = zero_vector;
//       }
//       //  else if (test_case == 1) {
//       //   input_1[0] = T_int(input_1[0]);
//       // }

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

//           for (auto j = 0u; j < number_of_parties; ++j) {
//             const T my_input_1 = party_id == j ? input_1.at(j) : 0;
//             share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, j));
//           }

//           auto share_compare = share_input_1[0].LTZ<T>(share_input_1[0]);

//           encrypto::motion::ShareWrapper share_output_1 = share_compare.Out(output_owner);
//           motion_parties.at(party_id)->Run();
//           if (party_id == output_owner) {
//             std::vector<T> comparison_result_1 = share_output_1.As<std::vector<T>>();
//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               bool expected_comparison_result_1 = T_int(input_1[i]) < 0;
//               EXPECT_EQ(bool(comparison_result_1[i]), expected_comparison_result_1);
//             }
//           }
//           motion_parties.at(party_id)->Finish();
//         }
//       } catch (std::exception& e) {
//         std::cerr << e.what() << std::endl;
//       }
//     }
//   };
//   for (auto i = 0ull; i < kTestIterations; ++i) {
//     template_test(static_cast<std::uint8_t>(0), static_cast<std::int8_t>(0));
//     template_test(static_cast<std::uint16_t>(0), static_cast<std::int16_t>(0));
//     template_test(static_cast<std::uint32_t>(0), static_cast<std::int32_t>(0));
//     template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0));
//     template_test(static_cast<__uint128_t>(0), static_cast<__int128_t>(0));  // should support
//     // now
//   }
// }


// TEST(ArithmeticGmw, LT_10_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable1, auto template_variable2) {
//     using T = decltype(template_variable1);
//     using T_int = decltype(template_variable2);
//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = std::rand() % number_of_parties;
//       std::size_t num_of_simd = 10;

//       std::vector<T> input_1 = ::RandomVector<T>(num_of_simd);
//       std::vector<T> input_2 = ::RandomVector<T>(num_of_simd);

//       // test for edge case:
//       mt19937 mt(time(nullptr));
//       std::size_t edge_case = mt() % 8;
//       std::vector<T> zero_vector(num_of_simd, 0);
//       if (edge_case == 0) {
//         input_2 = zero_vector;
//       } else if (edge_case == 1) {
//         input_1 = zero_vector;
//       } else if (edge_case == 2) {
//         input_2 = input_1;
//       } else if (edge_case == 3) {
//         input_2 = zero_vector;
//         input_1 = zero_vector;
//       }

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
//           std::vector<encrypto::motion::ShareWrapper> share_input_2;

//           share_input_1.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_1, 0));
//           share_input_2.push_back(motion_parties.at(party_id)->In<kArithmeticGmw>(input_2, 0));

//           auto share_compare = share_input_1[0].LT<T>(share_input_1[0], share_input_2[0]);

//           // ShareWrapper arithemtic_gmw_share_a_minus_b = share_input_1[0] - share_input_2[0];

//           encrypto::motion::ShareWrapper share_output_1 = share_compare.Out(output_owner);
//           // encrypto::motion::ShareWrapper arithemtic_gmw_share_a_minus_b_out =
//           //     arithemtic_gmw_share_a_minus_b.Out(output_owner);
//           motion_parties.at(party_id)->Run();
//           if (party_id == output_owner) {
//             // std::vector<T> arithemtic_gmw_share_a_minus_b_out_as =
//             //     arithemtic_gmw_share_a_minus_b_out.As<std::vector<T>>();
//             std::vector<T> comparison_result_1 = share_output_1.As<std::vector<T>>();
//             for (std::size_t i = 0; i < num_of_simd; ++i) {
//               bool expected_comparison_result_1 = T_int(input_1[i] - input_2[i]) < 0;
//               EXPECT_EQ(bool(comparison_result_1[i]), expected_comparison_result_1);
//             }
//           }
//           motion_parties.at(party_id)->Finish();
//         }
//       } catch (std::exception& e) {
//         std::cerr << e.what() << std::endl;
//       }
//     }
//   };
//   for (auto i = 0ull; i < kTestIterations; ++i) {
//     template_test(static_cast<std::uint8_t>(0), static_cast<std::int8_t>(0));
//     template_test(static_cast<std::uint16_t>(0), static_cast<std::int16_t>(0));
//     template_test(static_cast<std::uint32_t>(0), static_cast<std::int32_t>(0));
//     template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0));
//     template_test(static_cast<__uint128_t>(0), static_cast<__int128_t>(0));  // should support
//     // now
//   }
// }
