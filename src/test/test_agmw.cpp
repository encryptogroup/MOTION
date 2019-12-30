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
#include "gate/arithmetic_gmw_gate.h"
#include "share/share_wrapper.h"
#include "test_constants.h"
#include "test_helpers.h"
#include "wire/arithmetic_gmw_wire.h"

using namespace MOTION;

TEST(ArithmeticGMW, InputOutput_1_1K_SIMD_2_3_4_5_10_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    for (auto num_parties : num_parties_list) {
      std::size_t input_owner = std::rand() % num_parties, output_owner = std::rand() % num_parties;
      using T = decltype(template_var);
      T global_input_1 = Rand<T>();
      std::vector<T> global_input_1K = RandomVector<T>(1000);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          T input_1 = 0u;
          std::vector<T> input_1K(global_input_1K.size(), 0u);
          if (party_id == input_owner) {
            input_1 = global_input_1;
            input_1K = global_input_1K;
          }

          MOTION::Shares::ShareWrapper s_in_1 =
              motion_parties.at(party_id)->IN<AGMW>(input_1, input_owner);
          MOTION::Shares::ShareWrapper s_in_1K =
              motion_parties.at(party_id)->IN<AGMW>(input_1K, input_owner);

          auto s_out_1 = s_in_1.Out(output_owner);
          auto s_out_1K = s_in_1K.Out(output_owner);

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);
            EXPECT_EQ(wire_1->GetValues().at(0), global_input_1);
            EXPECT_TRUE(Helpers::Compare::Vectors(wire_1K->GetValues(), global_input_1K));
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(ArithmeticGMW, Addition_1_1K_SIMD_2_3_4_5_10_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_1K(1000, 0);
    for (auto num_parties : num_parties_list) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties);
      std::vector<std::vector<T>> in_1K(num_parties);
      for (auto &v : in_1K) {
        v = RandomVector<T>(1000);
      }
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_1K = party_id == j ? in_1K.at(j) : _zero_v_1K;

            s_in_1.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_1K.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1K, j));
          }

          auto s_add_1 = s_in_1.at(0) + s_in_1.at(1);
          auto s_add_1K = s_in_1K.at(0) + s_in_1K.at(1);

          for (auto j = 2u; j < num_parties; ++j) {
            s_add_1 += s_in_1.at(j);
            s_add_1K += s_in_1K.at(j);
          }

          auto s_out_1 = s_add_1.Out(output_owner);
          auto s_out_1K = s_add_1K.Out(output_owner);

          auto s_out_1_all = s_add_1.Out();
          auto s_out_1K_all = s_add_1K.Out();

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = wire_1K->GetValues();
            const std::vector<T> expected_result_1K = std::move(Helpers::RowSumReduction(in_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
          }

          {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1_all->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K_all->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = wire_1K->GetValues();
            const std::vector<T> expected_result_1K = std::move(Helpers::RowSumReduction(in_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(ArithmeticGMW, ConstantAddition_1_1K_SIMD_2_3_4_5_10_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  constexpr auto ACONST = MOTION::MPCProtocol::ArithmeticConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_1K(1000, 0);
    for (auto num_parties : num_parties_list) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties), const_in_1 = RandomVector<T>(1),
                     const_in_1K = RandomVector<T>(1000);
      std::vector<std::vector<T>> in_1K(num_parties);
      for (auto &v : in_1K) {
        v = RandomVector<T>(1000);
      }
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_1K = party_id == j ? in_1K.at(j) : _zero_v_1K;

            s_in_1.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_1K.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1K, j));
          }

          MOTION::Shares::ShareWrapper s_const_in_1 =
              motion_parties.at(party_id)->IN<ACONST>(const_in_1);
          MOTION::Shares::ShareWrapper s_const_in_1K =
              motion_parties.at(party_id)->IN<ACONST>(const_in_1K);

          auto s_add_1 = s_in_1.at(0) + s_in_1.at(1);
          auto s_add_1K = s_in_1K.at(0) + s_in_1K.at(1);

          for (auto j = 2u; j < num_parties; ++j) {
            s_add_1 += s_in_1.at(j);
            s_add_1K += s_in_1K.at(j);
          }

          s_add_1 += s_const_in_1;
          s_add_1K += s_const_in_1K;

          auto s_out_1 = s_add_1.Out(output_owner);
          auto s_out_1K = s_add_1K.Out(output_owner);

          auto s_out_1_all = s_add_1.Out();
          auto s_out_1K_all = s_add_1K.Out();

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1) + const_in_1.at(0);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = {wire_1K->GetValues()};
            const auto tmp_result{Helpers::RowSumReduction(in_1K)};
            const auto expected_result_1K{Helpers::AddVectors(const_in_1K, tmp_result)};
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K, expected_result_1K);
            }
          }

          {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1_all->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K_all->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1) + const_in_1.at(0);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = {wire_1K->GetValues()};
            const auto tmp_result{Helpers::RowSumReduction(in_1K)};
            const auto expected_result_1K{Helpers::AddVectors(const_in_1K, tmp_result)};
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K, expected_result_1K);
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(ArithmeticGMW, Subtraction_1_1K_SIMD_2_3_4_5_10_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_1K(1000, 0);
    for (auto num_parties : num_parties_list) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties);
      std::vector<std::vector<T>> in_1K(num_parties);
      for (auto &v : in_1K) {
        v = RandomVector<T>(1000);
      }
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_1K = party_id == j ? in_1K.at(j) : _zero_v_1K;

            s_in_1.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_1K.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1K, j));
          }

          auto s_sub_1 = s_in_1.at(0) - s_in_1.at(1);
          auto s_sub_1K = s_in_1K.at(0) - s_in_1K.at(1);

          for (auto j = 2u; j < num_parties; ++j) {
            s_sub_1 -= s_in_1.at(j);
            s_sub_1K -= s_in_1K.at(j);
          }

          auto s_out_1 = s_sub_1.Out(output_owner);
          auto s_out_1K = s_sub_1K.Out(output_owner);

          auto s_out_1_all = s_sub_1.Out();
          auto s_out_1K_all = s_sub_1K.Out();

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SubReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = wire_1K->GetValues();
            const std::vector<T> expected_result_1K = std::move(Helpers::RowSubReduction(in_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
          }

          {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1_all->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K_all->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SubReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = wire_1K->GetValues();
            const std::vector<T> expected_result_1K = Helpers::RowSubReduction(in_1K);
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(ArithmeticGMW, Multiplication_1_100_SIMD_2_3_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_100(100, 0);
    for (auto num_parties : {2u, 3u}) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties);
      std::vector<std::vector<T>> in_100(num_parties);
      for (auto &v : in_100) {
        v = RandomVector<T>(100);
      }
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_100;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_100 = party_id == j ? in_100.at(j) : _zero_v_100;

            s_in_1.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_100.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_100, j));
          }

          auto s_mul_1 = s_in_1.at(0) * s_in_1.at(1);
          auto s_mul_100 = s_in_100.at(0) * s_in_100.at(1);

          for (auto j = 2u; j < num_parties; ++j) {
            s_mul_1 *= s_in_1.at(j);
            s_mul_100 *= s_in_100.at(j);
          }

          auto s_out_1 = s_mul_1.Out(output_owner);
          auto s_out_1K = s_mul_100.Out(output_owner);

          auto s_out_1_all = s_mul_1.Out();
          auto s_out_100_all = s_mul_100.Out();

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_100 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::RowMulReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_100 = wire_100->GetValues();
            const std::vector<T> expected_result_100 = std::move(Helpers::RowMulReduction(in_100));
            for (auto i = 0u; i < circuit_result_100.size(); ++i) {
              EXPECT_EQ(circuit_result_100.at(i), expected_result_100.at(i));
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}


TEST(ArithmeticGMW, ConstantMultiplication_1_1K_SIMD_2_3_4_5_10_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  constexpr auto ACONST = MOTION::MPCProtocol::ArithmeticConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_1K(1000, 0);
    for (auto num_parties : num_parties_list) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties), const_in_1 = RandomVector<T>(1),
          const_in_1K = RandomVector<T>(1000);
      std::vector<std::vector<T>> in_1K(num_parties);
      for (auto &v : in_1K) {
        v = RandomVector<T>(1000);
      }
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_1K = party_id == j ? in_1K.at(j) : _zero_v_1K;

            s_in_1.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_1K.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1K, j));
          }

          MOTION::Shares::ShareWrapper s_const_in_1 =
              motion_parties.at(party_id)->IN<ACONST>(const_in_1);
          MOTION::Shares::ShareWrapper s_const_in_1K =
              motion_parties.at(party_id)->IN<ACONST>(const_in_1K);

          auto s_add_1 = s_in_1.at(0) + s_in_1.at(1);
          auto s_add_1K = s_in_1K.at(0) + s_in_1K.at(1);

          for (auto j = 2u; j < num_parties; ++j) {
            s_add_1 += s_in_1.at(j);
            s_add_1K += s_in_1K.at(j);
          }

          s_add_1 *= s_const_in_1;
          s_add_1K *= s_const_in_1K;

          auto s_out_1 = s_add_1.Out(output_owner);
          auto s_out_1K = s_add_1K.Out(output_owner);

          auto s_out_1_all = s_add_1.Out();
          auto s_out_1K_all = s_add_1K.Out();

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1) * const_in_1.at(0);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = {wire_1K->GetValues()};
            const auto tmp_result{Helpers::RowSumReduction(in_1K)};
            const auto expected_result_1K{Helpers::MultiplyVectors(const_in_1K, tmp_result)};
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K, expected_result_1K);
            }
          }

          {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1_all->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K_all->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1) * const_in_1.at(0);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = {wire_1K->GetValues()};
            const auto tmp_result{Helpers::RowSumReduction(in_1K)};
            const auto expected_result_1K{Helpers::MultiplyVectors(const_in_1K, tmp_result)};
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K, expected_result_1K);
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}