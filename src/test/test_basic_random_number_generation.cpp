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
#include "secure_dp_mechanism/secure_dp_mechanism_helper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/print_uint128_t.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {

TEST(BooleanGmwOperation, PreOrL_1_bit_200_Simd_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < kTestIterations; ++i) {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::srand(std::time(nullptr));

    std::size_t num_of_simd = 100;
    std::size_t num_of_bit = std::rand() % 200 + 2;

    // std::cout << "num_of_bit: " << num_of_bit << std::endl;
 
    for (auto number_of_parties : kNumberOfPartiesList) {
      const std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<encrypto::motion::BitVector<>> global_input(num_of_bit);
      for (auto& bv : global_input) {
        bv = encrypto::motion::BitVector<>::SecureRandom(num_of_simd);
      }
      encrypto::motion::BitVector<> dummy_input = encrypto::motion::BitVector<>(num_of_simd, false);

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
          encrypto::motion::ShareWrapper share_input;
          for (auto j = 0ull; j < number_of_parties; ++j) {
            if (0 == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              share_input = (motion_parties.at(party_id)->In<kBooleanGmw>(global_input, 0));
            } else {
              share_input = (motion_parties.at(party_id)->In<kBooleanGmw>(global_input, 0));
            }
          }
          auto share_concatenate = share_input;
          auto share_pre_or = SecureDPMechanismHelper(share_concatenate).PreOrL();
          std::vector<encrypto::motion::ShareWrapper> share_pre_or_vector = share_pre_or.Split();

          std::vector<encrypto::motion::ShareWrapper> share_pre_or_out_vector;
          for (auto i = 0ull; i < num_of_bit; ++i) {
            share_pre_or_out_vector.push_back(share_pre_or_vector.at(i).Out());
          }

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            for (auto pre_or_index = 0ull; pre_or_index < num_of_bit; ++pre_or_index) {
              auto wire_output =
                  std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
                      share_pre_or_out_vector.at(pre_or_index)->GetWires().at(0));
              assert(wire_output);

              std::vector<encrypto::motion::BitVector<>> global_input_tmp;
              for (auto k = 0ull; k < pre_or_index + 1; ++k) {
                global_input_tmp.push_back(global_input.at(k));
              }
              if (pre_or_index == 0) {
                EXPECT_EQ(wire_output->GetValues(), global_input_tmp.at(0));
              } else {
                EXPECT_EQ(wire_output->GetValues(),
                          encrypto::motion::BitVector<>::OrBitVectors(global_input_tmp));
              }
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BasicRandomNumberGeneration, GeometricSampling1_1_Simd_2_3_4_5_10_parties) {
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
              SecureDPMechanismHelper(share_input_random_bits_1022)
                  .SimpleGeometricSampling_1(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            bool geometric_sample_bool_array[share_geometric_sample_bit_size];

            for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
              geometric_sample_bool_array[i] = share_output_bit_vector[i].As<bool>();
            }

            T geometric_sample =
                BoolArrayToInteger<T>(geometric_sample_bool_array, share_geometric_sample_bit_size);

            T expected_geometric_sample =
                bool_vector_geometric_sampling<T>(random_bits_1022_vector);
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

TEST(BasicRandomNumberGeneration, GeometricSampling1_100_Simd_2_3_4_5_10_parties) {
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
              SecureDPMechanismHelper(share_input_random_bits_1022)
                  .SimpleGeometricSampling_1(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

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

              std::vector<bool> random_bits_1022_vector_tmp(random_bits_length);
              for (std::size_t j = 0; j < random_bits_length; j++) {
                random_bits_1022_vector_tmp[j] = random_bits_1022_bit_vector_vector[j][i];
              }

              T expected_geometric_sample =
                  bool_vector_geometric_sampling<T>(random_bits_1022_vector_tmp);
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

TEST(BasicRandomNumberGeneration, GeometricSampling0_1_Simd_2_3_4_5_10_parties) {
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
              SecureDPMechanismHelper(share_input_random_bits_1022)
                  .SimpleGeometricSampling_0(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            bool geometric_sample_bool_array[share_geometric_sample_bit_size];

            for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
              geometric_sample_bool_array[i] = share_output_bit_vector[i].As<bool>();
            }

            T geometric_sample =
                BoolArrayToInteger<T>(geometric_sample_bool_array, share_geometric_sample_bit_size);

            T expected_geometric_sample =
                bool_vector_geometric_sampling<T>(random_bits_1022_vector) - 1;
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

TEST(BasicRandomNumberGeneration, GeometricSampling0_100_Simd_2_3_4_5_10_parties) {
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
              SecureDPMechanismHelper(share_input_random_bits_1022)
                  .SimpleGeometricSampling_0(share_input_random_bits_1022);

          std::size_t share_geometric_sample_bit_size = share_geometric_sample.Split().size();

          std::vector<encrypto::motion::ShareWrapper> share_output_bit_vector(
              share_geometric_sample_bit_size);
          for (std::size_t i = 0; i < share_geometric_sample_bit_size; i++) {
            share_output_bit_vector[i] = share_geometric_sample.Split().at(i).Out(output_owner);
          }

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

              std::vector<bool> random_bits_1022_vector_tmp(random_bits_length);
              for (std::size_t j = 0; j < random_bits_length; j++) {
                random_bits_1022_vector_tmp[j] = random_bits_1022_bit_vector_vector[j][i];
              }

              T expected_geometric_sample =
                  bool_vector_geometric_sampling<T>(random_bits_1022_vector_tmp) - 1;
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

TEST(BasicRandomNumberGeneration, UniformFloatingPoint32_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2) {
    using T = decltype(template_variable_1);
    using D = decltype(template_variable_2);

    std::size_t exponent_random_bits_length = 126;
    std::size_t mantissa_random_bits_length = 23;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::vector<bool> exponent_random_bits_vector = RandomBoolVector(exponent_random_bits_length);
      std::vector<bool> mantissa_random_bits_vector = RandomBoolVector(mantissa_random_bits_length);

      std::vector<BitVector<>> exponent_random_bits_bitvector_vector(exponent_random_bits_length);
      for (std::size_t i = 0; i < exponent_random_bits_length; i++) {
        exponent_random_bits_bitvector_vector[i] = BitVector<>(1, exponent_random_bits_vector[i]);
      }

      std::vector<BitVector<>> mantissa_random_bits_bitvector_vector(mantissa_random_bits_length);
      for (std::size_t i = 0; i < mantissa_random_bits_length; i++) {
        mantissa_random_bits_bitvector_vector[i] = BitVector<>(1, mantissa_random_bits_vector[i]);
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
          encrypto::motion::ShareWrapper share_input_exponent_random_bits;
          encrypto::motion::ShareWrapper share_input_mantissa_random_bits;

          share_input_exponent_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              exponent_random_bits_bitvector_vector, 0);
          share_input_mantissa_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              mantissa_random_bits_bitvector_vector, 0);

          SecureFloatingPointCircuitABY share_uniform_floating_point_32 =
              SecureDPMechanismHelper(share_input_exponent_random_bits)
                  .UniformFloatingPoint32_0_1(share_input_mantissa_random_bits,
                                              share_input_exponent_random_bits);

          SecureFloatingPointCircuitABY share_uniform_floating_point_32_out =
              share_uniform_floating_point_32.Out();

          SecureFloatingPointCircuitABY share_uniform_floating_point_32_64_out =
              share_uniform_floating_point_32.ConvertSinglePrecisionToDoublePrecision().Out();

          SecureFloatingPointCircuitABY share_uniform_floating_point_32_64_32_out =
              share_uniform_floating_point_32.ConvertSinglePrecisionToDoublePrecision()
                  .ConvertDoublePrecisionToSinglePrecision()
                  .Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            T uniform_floating_point_T = share_uniform_floating_point_32_out.As<T>();

            float uniform_floating_point_32 =
                share_uniform_floating_point_32_out.AsFloatingPoint<float>();

            float expect_uniform_floating_point = uniform_floating_point32_0_1(
                mantissa_random_bits_vector, exponent_random_bits_vector);

            D uniform_floating_point_32_64_D = share_uniform_floating_point_32_64_out.As<D>();

            double uniform_floating_point_32_64 =
                share_uniform_floating_point_32_64_out.AsFloatingPoint<double>();

            T uniform_floating_point_32_64_32_T = share_uniform_floating_point_32_64_32_out.As<T>();

            float uniform_floating_point_32_64_32 =
                share_uniform_floating_point_32_64_32_out.AsFloatingPoint<float>();

            EXPECT_EQ(expect_uniform_floating_point, uniform_floating_point_32);
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint32_t>(0), static_cast<std::uint64_t>(0));
  }
}

TEST(BasicRandomNumberGeneration, UniformFloatingPoint32_100_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2) {
    using T = decltype(template_variable_1);
    using D = decltype(template_variable_2);

    std::size_t num_of_simd = 100;

    std::size_t exponent_random_bits_length = 126;
    std::size_t mantissa_random_bits_length = 23;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::vector<BitVector<>> exponent_random_bits_bitvector_vector(exponent_random_bits_length);
      for (std::size_t i = 0; i < exponent_random_bits_length; i++) {
        exponent_random_bits_bitvector_vector[i] = BitVector<>::SecureRandom(num_of_simd);
      }

      std::vector<BitVector<>> mantissa_random_bits_bitvector_vector(mantissa_random_bits_length);
      for (std::size_t i = 0; i < mantissa_random_bits_length; i++) {
        mantissa_random_bits_bitvector_vector[i] = BitVector<>::SecureRandom(num_of_simd);
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
          encrypto::motion::ShareWrapper share_input_exponent_random_bits;
          encrypto::motion::ShareWrapper share_input_mantissa_random_bits;

          share_input_exponent_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              exponent_random_bits_bitvector_vector, 0);
          share_input_mantissa_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              mantissa_random_bits_bitvector_vector, 0);

          SecureFloatingPointCircuitABY share_uniform_floating_point_32 =
              SecureDPMechanismHelper(share_input_exponent_random_bits)
                  .UniformFloatingPoint32_0_1(share_input_mantissa_random_bits,
                                              share_input_exponent_random_bits);

          SecureFloatingPointCircuitABY share_uniform_floating_point_32_out =
              share_uniform_floating_point_32.Out();

          SecureFloatingPointCircuitABY share_uniform_floating_point_32_64_out =
              share_uniform_floating_point_32.ConvertSinglePrecisionToDoublePrecision().Out();

          SecureFloatingPointCircuitABY share_uniform_floating_point_32_64_32_out =
              share_uniform_floating_point_32.ConvertSinglePrecisionToDoublePrecision()
                  .ConvertDoublePrecisionToSinglePrecision()
                  .Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<float> uniform_floating_point_32 =
                share_uniform_floating_point_32_out.AsFloatingPointVector<float>();

            std::vector<double> uniform_floating_point_32_64 =
                share_uniform_floating_point_32_64_out.AsFloatingPointVector<double>();

            std::vector<float> uniform_floating_point_32_64_32 =
                share_uniform_floating_point_32_64_32_out.AsFloatingPointVector<float>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              std::vector<bool> mantissa_random_bits_vector_tmp(mantissa_random_bits_length);
              std::vector<bool> exponent_random_bits_vector_tmp(exponent_random_bits_length);

              for (std::size_t j = 0; j < mantissa_random_bits_length; j++) {
                mantissa_random_bits_vector_tmp[j] = mantissa_random_bits_bitvector_vector[j][i];
              }
              for (std::size_t j = 0; j < exponent_random_bits_length; j++) {
                exponent_random_bits_vector_tmp[j] = exponent_random_bits_bitvector_vector[j][i];
              }

              float expect_uniform_floating_point = uniform_floating_point32_0_1(
                  mantissa_random_bits_vector_tmp, exponent_random_bits_vector_tmp);

              EXPECT_EQ(expect_uniform_floating_point, uniform_floating_point_32[i]);

              double abs_error = 0.0001;
              EXPECT_NEAR(uniform_floating_point_32[i], uniform_floating_point_32_64[i], abs_error);
              EXPECT_NEAR(uniform_floating_point_32[i], uniform_floating_point_32_64_32[i],
                          abs_error);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint32_t>(0), static_cast<std::uint64_t>(0));
  }
}

TEST(BasicRandomNumberGeneration, UniformFloatingPoint64_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);

    std::size_t exponent_random_bits_length = 1022;
    std::size_t mantissa_random_bits_length = 52;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::vector<bool> exponent_random_bits_vector = RandomBoolVector(exponent_random_bits_length);
      std::vector<bool> mantissa_random_bits_vector = RandomBoolVector(mantissa_random_bits_length);

      std::vector<BitVector<>> exponent_random_bits_bitvector_vector(exponent_random_bits_length);
      for (std::size_t i = 0; i < exponent_random_bits_length; i++) {
        exponent_random_bits_bitvector_vector[i] = BitVector<>(1, exponent_random_bits_vector[i]);
      }

      std::vector<BitVector<>> mantissa_random_bits_bitvector_vector(mantissa_random_bits_length);
      for (std::size_t i = 0; i < mantissa_random_bits_length; i++) {
        mantissa_random_bits_bitvector_vector[i] = BitVector<>(1, mantissa_random_bits_vector[i]);
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
          encrypto::motion::ShareWrapper share_input_exponent_random_bits;
          encrypto::motion::ShareWrapper share_input_mantissa_random_bits;

          share_input_exponent_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              exponent_random_bits_bitvector_vector, 0);
          share_input_mantissa_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              mantissa_random_bits_bitvector_vector, 0);

          SecureFloatingPointCircuitABY share_uniform_floating_point =
              SecureDPMechanismHelper(share_input_exponent_random_bits)
                  .UniformFloatingPoint64_0_1(share_input_mantissa_random_bits,
                                              share_input_exponent_random_bits);

          SecureFloatingPointCircuitABY share_uniform_floating_point_out =
              share_uniform_floating_point.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            T uniform_floating_point_T = share_uniform_floating_point_out.As<T>();

            double uniform_floating_point =
                share_uniform_floating_point_out.AsFloatingPoint<double>();

            double expect_uniform_floating_point = uniform_floating_point64_0_1(
                mantissa_random_bits_vector, exponent_random_bits_vector);

            EXPECT_EQ(expect_uniform_floating_point, uniform_floating_point);
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

TEST(BasicRandomNumberGeneration, UniformFloatingPoint64_100_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2) {
    using T = decltype(template_variable_1);
    using D = decltype(template_variable_2);

    std::size_t num_of_simd = 100;

    std::size_t exponent_random_bits_length = 1022;
    std::size_t mantissa_random_bits_length = 52;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::vector<BitVector<>> exponent_random_bits_bitvector_vector(exponent_random_bits_length);
      for (std::size_t i = 0; i < exponent_random_bits_length; i++) {
        exponent_random_bits_bitvector_vector[i] = BitVector<>::SecureRandom(num_of_simd);
      }

      std::vector<BitVector<>> mantissa_random_bits_bitvector_vector(mantissa_random_bits_length);
      for (std::size_t i = 0; i < mantissa_random_bits_length; i++) {
        mantissa_random_bits_bitvector_vector[i] = BitVector<>::SecureRandom(num_of_simd);
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
          encrypto::motion::ShareWrapper share_input_exponent_random_bits;
          encrypto::motion::ShareWrapper share_input_mantissa_random_bits;

          share_input_exponent_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              exponent_random_bits_bitvector_vector, 0);
          share_input_mantissa_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              mantissa_random_bits_bitvector_vector, 0);

          SecureFloatingPointCircuitABY share_uniform_floating_point_64 =
              SecureDPMechanismHelper(share_input_exponent_random_bits)
                  .UniformFloatingPoint64_0_1(share_input_mantissa_random_bits,
                                              share_input_exponent_random_bits);

          SecureFloatingPointCircuitABY share_uniform_floating_point_64_out =
              share_uniform_floating_point_64.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<double> uniform_floating_point_64 =
                share_uniform_floating_point_64_out.AsFloatingPointVector<double>();
            for (std::size_t i = 0; i < num_of_simd; i++) {
              std::vector<bool> mantissa_random_bits_vector_tmp(mantissa_random_bits_length);
              std::vector<bool> exponent_random_bits_vector_tmp(exponent_random_bits_length);

              for (std::size_t j = 0; j < mantissa_random_bits_length; j++) {
                mantissa_random_bits_vector_tmp[j] = mantissa_random_bits_bitvector_vector[j][i];
              }
              for (std::size_t j = 0; j < exponent_random_bits_length; j++) {
                exponent_random_bits_vector_tmp[j] = exponent_random_bits_bitvector_vector[j][i];
              }

              double expect_uniform_floating_point = uniform_floating_point64_0_1(
                  mantissa_random_bits_vector_tmp, exponent_random_bits_vector_tmp);

              EXPECT_EQ(expect_uniform_floating_point, uniform_floating_point_64[i]);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), static_cast<std::uint64_t>(0));
  }
}

// test passed
TEST(BasicRandomNumberGeneration, UniformFixedPoint_0_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = std::int64_t;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 1;
      T m = std::rand();
      std::size_t fixed_point_fraction_bit_size = 16;
      std::size_t fixed_point_bit_size = 64;

      std::vector<bool> bernoulli_sample_vector = rand_bool_vector(fixed_point_fraction_bit_size);

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
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_vector(
              fixed_point_fraction_bit_size);
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < fixed_point_fraction_bit_size; i++) {
            share_bernoulli_sample_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                BitVector<>(1, bernoulli_sample_vector[i]), 0);
          }

          share_x =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);

          SecureFixedPointCircuitCBMC share_result =
              SecureDPMechanismHelper(share_x).UniformFixedPoint_0_1(
                  ShareWrapper::Concatenate(share_bernoulli_sample_vector), fixed_point_bit_size);

          encrypto::motion::SecureFixedPointCircuitCBMC share_result_out = share_result.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<double> share_result_out_as =
                share_result_out.AsFixedPointVector<T, T_int>();

            for (std::size_t i = 0; i < share_result_out_as.size(); i++) {
              EXPECT_LT(share_result_out_as[i], 1);
              EXPECT_LE(0, share_result_out_as[i]);
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

TEST(BasicRandomNumberGeneration, UniformFixedPoint_0_100_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = std::int64_t;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 100;
      std::size_t fixed_point_fraction_bit_size = 16;
      std::size_t fixed_point_bit_size = 64;

      std::vector<BitVector<>> bernoulli_sample_vector(fixed_point_fraction_bit_size);
      for (std::size_t i = 0; i < fixed_point_fraction_bit_size; i++) {
        bernoulli_sample_vector[i] = BitVector<>::SecureRandom(num_of_simd);
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
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_vector(
              fixed_point_fraction_bit_size);
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < fixed_point_fraction_bit_size; i++) {
            share_bernoulli_sample_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(bernoulli_sample_vector[i], 0);
          }

          share_x =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);

          SecureFixedPointCircuitCBMC share_result =
              SecureDPMechanismHelper(share_x).UniformFixedPoint_0_1(
                  ShareWrapper::Concatenate(share_bernoulli_sample_vector), fixed_point_bit_size);

          encrypto::motion::SecureFixedPointCircuitCBMC share_result_out = share_result.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<double> share_result_out_as =
                share_result_out.AsFixedPointVector<T, T_int>();

            for (std::size_t i = 0; i < share_result_out_as.size(); i++) {
              EXPECT_LT(share_result_out_as[i], 1);
              EXPECT_LE(0, share_result_out_as[i]);
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

TEST(BasicRandomNumberGeneration, UniformFixedPoint_0_1_Up_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = std::int64_t;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      T m = std::rand();
      std::size_t fixed_point_fraction_bit_size = 16;
      std::size_t fixed_point_bit_size = 64;

      std::vector<bool> bernoulli_sample_vector = rand_bool_vector(fixed_point_fraction_bit_size);

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
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_vector(
              fixed_point_fraction_bit_size);
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < fixed_point_fraction_bit_size; i++) {
            share_bernoulli_sample_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                BitVector<>(1, bernoulli_sample_vector[i]), 0);
          }

          share_x =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);

          SecureFixedPointCircuitCBMC share_result =
              SecureDPMechanismHelper(share_x).UniformFixedPoint_0_1_Up(
                  ShareWrapper::Concatenate(share_bernoulli_sample_vector), fixed_point_bit_size);

          encrypto::motion::SecureFixedPointCircuitCBMC share_result_out = share_result.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<double> share_result_out_as =
                share_result_out.AsFixedPointVector<T, T_int>();

            for (std::size_t i = 0; i < share_result_out_as.size(); i++) {
              EXPECT_LE(share_result_out_as[i], 1);
              EXPECT_LT(0, share_result_out_as[i]);
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

TEST(BasicRandomNumberGeneration, UniformFixedPoint_0_1_Up_100_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = std::int64_t;
    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 100;
      // T m = std::rand();
      std::size_t fixed_point_fraction_bit_size = 16;
      std::size_t fixed_point_bit_size = 64;

      std::vector<BitVector<>> bernoulli_sample_vector(fixed_point_fraction_bit_size);
      for (std::size_t i = 0; i < fixed_point_fraction_bit_size; i++) {
        bernoulli_sample_vector[i] = BitVector<>::SecureRandom(num_of_simd);
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
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_vector(
              fixed_point_fraction_bit_size);
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < fixed_point_fraction_bit_size; i++) {
            share_bernoulli_sample_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(bernoulli_sample_vector[i], 0);
          }

          share_x =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);

          SecureFixedPointCircuitCBMC share_result =
              SecureDPMechanismHelper(share_x).UniformFixedPoint_0_1_Up(
                  ShareWrapper::Concatenate(share_bernoulli_sample_vector), fixed_point_bit_size);

          encrypto::motion::SecureFixedPointCircuitCBMC share_result_out = share_result.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<double> share_result_out_as =
                share_result_out.AsFixedPointVector<T, T_int>();

            for (std::size_t i = 0; i < share_result_out_as.size(); i++) {
              EXPECT_LE(share_result_out_as[i], 1);
              EXPECT_LT(0, share_result_out_as[i]);
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

TEST(BasicRandomNumberGeneration, GenerateRandomUnsignedInteger_20_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 20;
      T m = std::rand() ;

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
          encrypto::motion::ShareWrapper share_random_unsigned_integer_0_m_vector;
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < num_of_simd; i++) {
            share_x =
                motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);
          }

          SecureUnsignedInteger share_result =
              SecureDPMechanismHelper(share_x).GenerateRandomUnsignedInteger(m, num_of_simd);

          encrypto::motion::SecureUnsignedInteger share_result_out = share_result.Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_out_as = share_result_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              EXPECT_LT(share_result_out_as[i], m);
              EXPECT_LT(0, share_result_out_as[i]);
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
    template_test(static_cast<__uint128_t>(0));
  }
}

}  // namespace
