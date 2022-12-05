// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko, Arianne Roselina Prananto
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

#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_discrete_gaussian_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_dp_mechanism_PrivaDA.h"
#include "secure_dp_mechanism/secure_gaussian_mechanism_CrypTen.h"
#include "secure_dp_mechanism/secure_integer_scaling_gaussian_mechanism.h"
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/integer_scaling_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {

// =================================================================
// test discrete laplace mechanism

// not check correctness of the calculation
// only check if interface works correctly
TEST(DiscreteGaussianMechanism_CKS,
     SecureDiscreteGaussianMechanismFL32_GC_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dgau = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dgau);

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double sigma = 1.5;
      long double failure_probability_requirement = std::exp2l(-20);

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
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kGarbledCircuit>(ToInput<T>(fD_vector), 0);

          SecureDiscreteGaussianMechanismCKS secure_discrete_gaussian_mechanism_CKS =
              SecureDiscreteGaussianMechanismCKS(share_fD);
          secure_discrete_gaussian_mechanism_CKS.ParameterSetup(
              sensitivity, sigma, num_of_simd_dgau, failure_probability_requirement);

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive =
              secure_discrete_gaussian_mechanism_CKS.FL32DiscreteGaussianNoiseGeneration_naive();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized =
              secure_discrete_gaussian_mechanism_CKS
                  .FL32DiscreteGaussianNoiseGeneration_optimized();

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive_out =
              signed_integer_discrete_gaussian_noise_naive.Out();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized_out =
              signed_integer_discrete_gaussian_noise_optimized.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_naive_out_as =
                signed_integer_discrete_gaussian_noise_naive_out.AsVector<T>();
            std::vector<T> share_result_0_optimized_out_as =
                signed_integer_discrete_gaussian_noise_optimized_out.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_naive_out_as.size(); ++i) {
              std::cout << "share_result_0_naive_out_as[i]: "
                        << T_int(share_result_0_naive_out_as[i]) << std::endl;
            }
            for (std::size_t i = 0; i < share_result_0_optimized_out_as.size(); ++i) {
              std::cout << "share_result_0_optimized_out_as[i]: "
                        << T_int(share_result_0_optimized_out_as[i]) << std::endl;
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(DiscreteGaussianMechanism_CKS,
     SecureDiscreteGaussianMechanismFL32_BGMW_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dgau = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dgau);

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double sigma = 1.5;
      long double failure_probability_requirement = std::exp2l(-20);

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
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(fD_vector), 0);

          SecureDiscreteGaussianMechanismCKS secure_discrete_gaussian_mechanism_CKS =
              SecureDiscreteGaussianMechanismCKS(share_fD);
          secure_discrete_gaussian_mechanism_CKS.ParameterSetup(
              sensitivity, sigma, num_of_simd_dgau, failure_probability_requirement);

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive =
              secure_discrete_gaussian_mechanism_CKS.FL32DiscreteGaussianNoiseGeneration_naive();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized =
              secure_discrete_gaussian_mechanism_CKS
                  .FL32DiscreteGaussianNoiseGeneration_optimized();

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive_out =
              signed_integer_discrete_gaussian_noise_naive.Out();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized_out =
              signed_integer_discrete_gaussian_noise_optimized.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_naive_out_as =
                signed_integer_discrete_gaussian_noise_naive_out.AsVector<T>();
            std::vector<T> share_result_0_optimized_out_as =
                signed_integer_discrete_gaussian_noise_optimized_out.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_naive_out_as.size(); ++i) {
              std::cout << "share_result_0_naive_out_as[i]: "
                        << T_int(share_result_0_naive_out_as[i]) << std::endl;
            }
            for (std::size_t i = 0; i < share_result_0_optimized_out_as.size(); ++i) {
              std::cout << "share_result_0_optimized_out_as[i]: "
                        << T_int(share_result_0_optimized_out_as[i]) << std::endl;
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

// ! cause memory overflow: >126 GB
// TEST(DiscreteGaussianMechanism_CKS,
//      SecureDiscreteGaussianMechanismFL32_BMR_Simd_2_3_4_5_10_parties) {
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
//   constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
//   constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
//   // std::srand(std::time(nullptr));
//   auto template_test = [](auto template_variable_1) {
//     using T = decltype(template_variable_1);
//     using T_int = get_int_type_t<T>;
//     using A = std::allocator<T>;
//     std::srand(std::time(nullptr));

//     for (auto number_of_parties : kNumberOfPartiesList) {
//       std::size_t output_owner = 0;

//       std::size_t num_of_simd_dgau = 1;
//       std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dgau);

//       std::cout << "fD_vector: " << std::endl;
//       for (std::size_t i = 0; i < fD_vector.size(); ++i) {
//         std::cout << fD_vector[i] << std::endl;
//       }

//       double sensitivity = 1;
//       double sigma = 1.5;
//       long double failure_probability_requirement = std::exp2l(-20);

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
//           encrypto::motion::ShareWrapper share_fD =
//               motion_parties.at(party_id)->In<kBmr>(ToInput<T>(fD_vector), 0);

//           SecureDiscreteGaussianMechanismCKS secure_discrete_gaussian_mechanism_CKS =
//               SecureDiscreteGaussianMechanismCKS(share_fD);
//           secure_discrete_gaussian_mechanism_CKS.ParameterSetup(
//               sensitivity, sigma, num_of_simd_dgau, failure_probability_requirement);

//           SecureSignedInteger signed_integer_discrete_gaussian_noise_naive =
//               secure_discrete_gaussian_mechanism_CKS.FL32DiscreteGaussianNoiseGeneration_naive();
//           SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized =
//               secure_discrete_gaussian_mechanism_CKS
//                   .FL32DiscreteGaussianNoiseGeneration_optimized();

//           SecureSignedInteger signed_integer_discrete_gaussian_noise_naive_out =
//               signed_integer_discrete_gaussian_noise_naive.Out();
//           SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized_out =
//               signed_integer_discrete_gaussian_noise_optimized.Out();

//           std::cout << "party run" << std::endl;
//           motion_parties.at(party_id)->Run();
//           motion_parties.at(party_id)->Finish();

//           if (party_id == 0) {
//             std::cout << "party_id: " << party_id << std::endl;
//             std::vector<T> share_result_0_naive_out_as =
//                 signed_integer_discrete_gaussian_noise_naive_out.AsVector<T>();
//             std::vector<T> share_result_0_optimized_out_as =
//                 signed_integer_discrete_gaussian_noise_optimized_out.AsVector<T>();

//             for (std::size_t i = 0; i < share_result_0_naive_out_as.size(); ++i) {
//               std::cout << "share_result_0_naive_out_as[i]: "
//                         << T_int(share_result_0_naive_out_as[i]) << std::endl;
//             }
//             for (std::size_t i = 0; i < share_result_0_optimized_out_as.size(); ++i) {
//               std::cout << "share_result_0_optimized_out_as[i]: "
//                         << T_int(share_result_0_optimized_out_as[i]) << std::endl;
//             }
//           }
//         }
//       } catch (std::exception& e) {
//         std::cerr << e.what() << std::endl;
//       }
//     }
//   };
//   for (auto i = 0ull; i < kTestIterations; ++i) {
//     template_test(static_cast<std::uint64_t>(0));
//   }
// }

TEST(DiscreteGaussianMechanism_CKS,
     SecureDiscreteGaussianMechanismFL64_GC_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dgau = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dgau);

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double sigma = 1.5;
      long double failure_probability_requirement = std::exp2l(-20);

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
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kGarbledCircuit>(ToInput<T>(fD_vector), 0);

          SecureDiscreteGaussianMechanismCKS secure_discrete_gaussian_mechanism_CKS =
              SecureDiscreteGaussianMechanismCKS(share_fD);
          secure_discrete_gaussian_mechanism_CKS.ParameterSetup(
              sensitivity, sigma, num_of_simd_dgau, failure_probability_requirement);

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive =
              secure_discrete_gaussian_mechanism_CKS.FL64DiscreteGaussianNoiseGeneration_naive();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized =
              secure_discrete_gaussian_mechanism_CKS
                  .FL64DiscreteGaussianNoiseGeneration_optimized();

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive_out =
              signed_integer_discrete_gaussian_noise_naive.Out();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized_out =
              signed_integer_discrete_gaussian_noise_optimized.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_naive_out_as =
                signed_integer_discrete_gaussian_noise_naive_out.AsVector<T>();
            std::vector<T> share_result_0_optimized_out_as =
                signed_integer_discrete_gaussian_noise_optimized_out.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_naive_out_as.size(); ++i) {
              std::cout << "share_result_0_naive_out_as[i]: "
                        << T_int(share_result_0_naive_out_as[i]) << std::endl;
            }
            for (std::size_t i = 0; i < share_result_0_optimized_out_as.size(); ++i) {
              std::cout << "share_result_0_optimized_out_as[i]: "
                        << T_int(share_result_0_optimized_out_as[i]) << std::endl;
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(DiscreteGaussianMechanism_CKS,
     SecureDiscreteGaussianMechanismFL64_BGMW_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dgau = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dgau);

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double sigma = 1.5;
      long double failure_probability_requirement = std::exp2l(-20);

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
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(fD_vector), 0);

          SecureDiscreteGaussianMechanismCKS secure_discrete_gaussian_mechanism_CKS =
              SecureDiscreteGaussianMechanismCKS(share_fD);
          secure_discrete_gaussian_mechanism_CKS.ParameterSetup(
              sensitivity, sigma, num_of_simd_dgau, failure_probability_requirement);

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive =
              secure_discrete_gaussian_mechanism_CKS.FL64DiscreteGaussianNoiseGeneration_naive();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized =
              secure_discrete_gaussian_mechanism_CKS
                  .FL64DiscreteGaussianNoiseGeneration_optimized();

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive_out =
              signed_integer_discrete_gaussian_noise_naive.Out();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized_out =
              signed_integer_discrete_gaussian_noise_optimized.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_naive_out_as =
                signed_integer_discrete_gaussian_noise_naive_out.AsVector<T>();
            std::vector<T> share_result_0_optimized_out_as =
                signed_integer_discrete_gaussian_noise_optimized_out.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_naive_out_as.size(); ++i) {
              std::cout << "share_result_0_naive_out_as[i]: "
                        << T_int(share_result_0_naive_out_as[i]) << std::endl;
            }
            for (std::size_t i = 0; i < share_result_0_optimized_out_as.size(); ++i) {
              std::cout << "share_result_0_optimized_out_as[i]: "
                        << T_int(share_result_0_optimized_out_as[i]) << std::endl;
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

// ! cause memory overflow: >126 GB
TEST(DiscreteGaussianMechanism_CKS,
     SecureDiscreteGaussianMechanismFL64_BMR_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dgau = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dgau);

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double sigma = 1.5;
      long double failure_probability_requirement = std::exp2l(-20);

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
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kBmr>(ToInput<T>(fD_vector), 0);

          SecureDiscreteGaussianMechanismCKS secure_discrete_gaussian_mechanism_CKS =
              SecureDiscreteGaussianMechanismCKS(share_fD);
          secure_discrete_gaussian_mechanism_CKS.ParameterSetup(
              sensitivity, sigma, num_of_simd_dgau, failure_probability_requirement);

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive =
              secure_discrete_gaussian_mechanism_CKS.FL64DiscreteGaussianNoiseGeneration_naive();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized =
              secure_discrete_gaussian_mechanism_CKS
                  .FL64DiscreteGaussianNoiseGeneration_optimized();

          SecureSignedInteger signed_integer_discrete_gaussian_noise_naive_out =
              signed_integer_discrete_gaussian_noise_naive.Out();
          SecureSignedInteger signed_integer_discrete_gaussian_noise_optimized_out =
              signed_integer_discrete_gaussian_noise_optimized.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_naive_out_as =
                signed_integer_discrete_gaussian_noise_naive_out.AsVector<T>();
            std::vector<T> share_result_0_optimized_out_as =
                signed_integer_discrete_gaussian_noise_optimized_out.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_naive_out_as.size(); ++i) {
              std::cout << "share_result_0_naive_out_as[i]: "
                        << T_int(share_result_0_naive_out_as[i]) << std::endl;
            }
            for (std::size_t i = 0; i < share_result_0_optimized_out_as.size(); ++i) {
              std::cout << "share_result_0_optimized_out_as[i]: "
                        << T_int(share_result_0_optimized_out_as[i]) << std::endl;
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

}  // namespace
