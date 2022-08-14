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

#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_discrete_laplace_mechanism_CKS.h"
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

// test discrete laplace mechanism
// not check correctness of the calculation
// only check if implementation is correct
TEST(DiscreteLaplaceMechanismCKS, SecureDiscreteLaplaceMechanismFL32_1_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dlap = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dlap);

      double sensitivity = 1;
      double scale = 2;

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

          SecureDiscreteLaplaceMechanismCKS secure_discrete_laplace_mechanism_CKS =
              SecureDiscreteLaplaceMechanismCKS(share_fD);
          secure_discrete_laplace_mechanism_CKS.ParameterSetup(sensitivity, scale, num_of_simd_dlap,
                                                               standard_fail_probability);

          SecureSignedInteger signed_integer_discrete_laplace_noise =
              secure_discrete_laplace_mechanism_CKS.FL32DiscreteLaplaceNoiseGeneration();

          SecureSignedInteger signed_integer_noisy_fD =
              secure_discrete_laplace_mechanism_CKS.FL32DiscreteLaplaceNoiseAddition();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out =
              signed_integer_discrete_laplace_noise.Out();
          SecureSignedInteger signed_integer_noisy_fD_out = signed_integer_noisy_fD.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::vector<T> share_result_0_out_as =
                signed_integer_discrete_laplace_noise_out.AsVector<T>();

            std::vector<T> signed_integer_noisy_fD_out_as =
                signed_integer_noisy_fD_out.AsVector<T>();

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
// not check correctness of the calculation
// only check if implementation is correct
TEST(DiscreteLaplaceMechanismCKS, SecureDiscreteLaplaceMechanismFL64_1_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dlap = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dlap);

      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double scale = 2;

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

          SecureDiscreteLaplaceMechanismCKS secure_discrete_laplace_mechanism_CKS =
              SecureDiscreteLaplaceMechanismCKS(share_fD);
          secure_discrete_laplace_mechanism_CKS.ParameterSetup(sensitivity, scale, num_of_simd_dlap,
                                                               standard_fail_probability);

          SecureSignedInteger signed_integer_discrete_laplace_noise =
              secure_discrete_laplace_mechanism_CKS.FL64DiscreteLaplaceNoiseGeneration();

          SecureSignedInteger signed_integer_noisy_fD =
              secure_discrete_laplace_mechanism_CKS.FL64DiscreteLaplaceNoiseAddition();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out =
              signed_integer_discrete_laplace_noise.Out();
          SecureSignedInteger signed_integer_noisy_fD_out = signed_integer_noisy_fD.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::vector<T> share_result_0_out_as =
                signed_integer_discrete_laplace_noise_out.AsVector<T>();

            std::vector<T> signed_integer_noisy_fD_out_as =
                signed_integer_noisy_fD_out.AsVector<T>();

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

// not check correctness of the calculation
// only check if implementation is correct
TEST(DiscreteLaplaceMechanismCKS, SecureDiscreteLaplaceMechanismFx_1_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_dlap = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_dlap);

      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double scale = 2;

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

          SecureDiscreteLaplaceMechanismCKS secure_discrete_laplace_mechanism_CKS =
              SecureDiscreteLaplaceMechanismCKS(share_fD);
          secure_discrete_laplace_mechanism_CKS.ParameterSetup(sensitivity, scale, num_of_simd_dlap,
                                                               standard_fail_probability);

          SecureSignedInteger signed_integer_discrete_laplace_noise =
              secure_discrete_laplace_mechanism_CKS.FxDiscreteLaplaceNoiseGeneration();

          SecureSignedInteger signed_integer_noisy_fD =
              secure_discrete_laplace_mechanism_CKS.FxDiscreteLaplaceNoiseAddition();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out =
              signed_integer_discrete_laplace_noise.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::vector<T> share_result_0_out_as =
                signed_integer_discrete_laplace_noise_out.AsVector<T>();

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
