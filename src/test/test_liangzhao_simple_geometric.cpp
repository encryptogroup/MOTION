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
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

#include "secure_dp_mechanism/secure_sampling_algorithm_naive.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {

TEST(BasicRandomNumberGeneration, SimpleGeometricSampling1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_vairable_2) {
    using T = decltype(template_variable_1);
    std::size_t random_bits_length = template_vairable_2;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = std::rand() % number_of_parties;

      std::vector<bool> random_bits_1022_vector = RandomBoolVector(random_bits_length);

      // // only for debug
      // for (std::size_t i = 0; i < random_bits_length; i++) {
      //         random_bits_1022_vector[i]=0;
      //       }

      std::cout << "random_bits_1022_vector: ";
      for (std::size_t i = 0; i < random_bits_length; i++) {
        std::cout << random_bits_1022_vector[i];
      }
      std::cout << std::endl;

      std::vector<BitVector<>> random_bits_1022_bit_vector_vector(random_bits_length);
      for (std::size_t i = 0; i < random_bits_length; i++) {
        random_bits_1022_bit_vector_vector[i] = BitVector<>(1, random_bits_1022_vector[i]);
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
          encrypto::motion::ShareWrapper share_input_random_bits_1022;
          share_input_random_bits_1022 =
              motion_parties.at(party_id)->In<kBooleanGmw>(random_bits_1022_bit_vector_vector, 0);

          auto share_geometric_sample =
              SecureSamplingAlgorithm_naive(share_input_random_bits_1022).SimpleGeometricSampling_1(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            bool geometric_sample_bool_array[share_geometric_sample_bit_size];

            std::cout << "geometric_sample_bool_array: ";
            for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
              geometric_sample_bool_array[i] = share_output_bit_vector[i].As<bool>();
              std::cout << geometric_sample_bool_array[i];
            }
            std::cout << std::endl;

            T geometric_sample =
                BoolArrayToInteger<T>(geometric_sample_bool_array, share_geometric_sample_bit_size);
            std::cout << "geometric_sample: " << geometric_sample << std::endl;

            T expected_geometric_sample =
                bool_vector_geometric_sampling<T>(random_bits_1022_vector);
            std::cout << "expect geometric_sample: " << expected_geometric_sample << std::endl;
            EXPECT_EQ(expected_geometric_sample, geometric_sample);
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), 1022);
  }
}

TEST(BasicRandomNumberGeneration, SimpleGeometricSampling1_100_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_vairable_2) {
    using T = decltype(template_variable_1);
    std::size_t random_bits_length = template_vairable_2;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = std::rand() % number_of_parties;

      std::size_t num_of_simd = 100;

      std::vector<BitVector<>> random_bits_1022_bit_vector_vector(random_bits_length);

      for (std::size_t i = 0; i < random_bits_length; i++) {
        random_bits_1022_bit_vector_vector[i] = BitVector<>::SecureRandom(num_of_simd);
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
          encrypto::motion::ShareWrapper share_input_random_bits_1022;
          share_input_random_bits_1022 =
              motion_parties.at(party_id)->In<kBooleanGmw>(random_bits_1022_bit_vector_vector, 0);

          auto share_geometric_sample =
              SecureSamplingAlgorithm_naive(share_input_random_bits_1022).SimpleGeometricSampling_1(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            for (std::size_t i = 0; i < num_of_simd; i++) {
              bool geometric_sample_bool_array[share_geometric_sample_bit_size];

              for (std::size_t k = 0; k < share_geometric_sample_bit_size; k++) {
                geometric_sample_bool_array[k] = share_output_bit_vector[k].As<BitVector<>>()[i];
              }
              T geometric_sample = BoolArrayToInteger<T>(geometric_sample_bool_array,
                                                         share_geometric_sample_bit_size);
              std::cout << "geometric_sample: " << geometric_sample << std::endl;

              std::vector<bool> random_bits_1022_vector_tmp(random_bits_length);
              for (std::size_t j = 0; j < random_bits_length; j++) {
                random_bits_1022_vector_tmp[j] = random_bits_1022_bit_vector_vector[j][i];
              }

              T expected_geometric_sample =
                  bool_vector_geometric_sampling<T>(random_bits_1022_vector_tmp);
              std::cout << "expect geometric_sample: " << expected_geometric_sample << std::endl;
              EXPECT_EQ(expected_geometric_sample, geometric_sample);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), 1022);
  }
}

TEST(BasicRandomNumberGeneration, SimpleGeometricSampling0_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_vairable_2) {
    using T = decltype(template_variable_1);
    std::size_t random_bits_length = template_vairable_2;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = std::rand() % number_of_parties;

      std::vector<bool> random_bits_1022_vector = RandomBoolVector(random_bits_length);

      // // only for debug
      // for (std::size_t i = 0; i < random_bits_length; i++) {
      //         random_bits_1022_vector[i]=0;
      //       }

      std::cout << "random_bits_1022_vector: ";
      for (std::size_t i = 0; i < random_bits_length; i++) {
        std::cout << random_bits_1022_vector[i];
      }
      std::cout << std::endl;

      std::vector<BitVector<>> random_bits_1022_bit_vector_vector(random_bits_length);
      for (std::size_t i = 0; i < random_bits_length; i++) {
        random_bits_1022_bit_vector_vector[i] = BitVector<>(1, random_bits_1022_vector[i]);
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
          encrypto::motion::ShareWrapper share_input_random_bits_1022;
          share_input_random_bits_1022 =
              motion_parties.at(party_id)->In<kBooleanGmw>(random_bits_1022_bit_vector_vector, 0);

          auto share_geometric_sample =
              SecureSamplingAlgorithm_naive(share_input_random_bits_1022).SimpleGeometricSampling_0(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            bool geometric_sample_bool_array[share_geometric_sample_bit_size];

            std::cout << "geometric_sample_bool_array: ";
            for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
              geometric_sample_bool_array[i] = share_output_bit_vector[i].As<bool>();
              std::cout << geometric_sample_bool_array[i];
            }
            std::cout << std::endl;

            T geometric_sample =
                BoolArrayToInteger<T>(geometric_sample_bool_array, share_geometric_sample_bit_size);
            std::cout << "geometric_sample: " << geometric_sample << std::endl;

            T expected_geometric_sample =
                bool_vector_geometric_sampling<T>(random_bits_1022_vector) - 1;
            std::cout << "expect geometric_sample: " << expected_geometric_sample << std::endl;
            EXPECT_EQ(expected_geometric_sample, geometric_sample);
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint64_t>(0), 1022);
  }
}

TEST(BasicRandomNumberGeneration, SimpleGeometricSampling0_100_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_vairable_2) {
    using T = decltype(template_variable_1);
    std::size_t random_bits_length = template_vairable_2;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = std::rand() % number_of_parties;

      std::size_t num_of_simd = 100;

      std::vector<BitVector<>> random_bits_1022_bit_vector_vector(random_bits_length);

      for (std::size_t i = 0; i < random_bits_length; i++) {
        random_bits_1022_bit_vector_vector[i] = BitVector<>::SecureRandom(num_of_simd);
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
          encrypto::motion::ShareWrapper share_input_random_bits_1022;
          share_input_random_bits_1022 =
              motion_parties.at(party_id)->In<kBooleanGmw>(random_bits_1022_bit_vector_vector, 0);

          auto share_geometric_sample =
              SecureSamplingAlgorithm_naive(share_input_random_bits_1022).SimpleGeometricSampling_0(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            for (std::size_t i = 0; i < num_of_simd; i++) {
              bool geometric_sample_bool_array[share_geometric_sample_bit_size];

              for (std::size_t k = 0; k < share_geometric_sample_bit_size; k++) {
                geometric_sample_bool_array[k] = share_output_bit_vector[k].As<BitVector<>>()[i];
              }
              T geometric_sample = BoolArrayToInteger<T>(geometric_sample_bool_array,
                                                         share_geometric_sample_bit_size);
              std::cout << "geometric_sample: " << geometric_sample << std::endl;

              std::vector<bool> random_bits_1022_vector_tmp(random_bits_length);
              for (std::size_t j = 0; j < random_bits_length; j++) {
                random_bits_1022_vector_tmp[j] = random_bits_1022_bit_vector_vector[j][i];
              }

              T expected_geometric_sample =
                  bool_vector_geometric_sampling<T>(random_bits_1022_vector_tmp) - 1;
              std::cout << "expect geometric_sample: " << expected_geometric_sample << std::endl;
              EXPECT_EQ(expected_geometric_sample, geometric_sample);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), 1022);
  }
}


}  // namespace
