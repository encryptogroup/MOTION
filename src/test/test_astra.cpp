// MIT License
//
// Copyright (c) 2019 Oliver Schick
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
#include <gtest/gtest.h>
#include "base/party.h"
#include "protocols/astra/astra_gate.h"
#include "protocols/astra/astra_wire.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"
#include "test_helpers.h"

#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#define BOOST_STACKTRACE_USE_ADDR2LINE
#include <boost/stacktrace.hpp>

void handler(int sig) {
  std::cout << boost::stacktrace::stacktrace() << std::endl;
  exit(1);
}

using namespace encrypto::motion;

auto rand_val = std::mt19937{};

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();

TEST(Astra, InputOutput_1_3_parties) {
  signal(SIGSEGV, handler);
  constexpr auto kAstra = encrypto::motion::MpcProtocol::kAstra;
  
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable) {
    for (auto number_of_parties : {3u}) {
      std::size_t input_owner = std::rand() % number_of_parties,
                  output_owner = kAll;
      using T = decltype(template_variable);
      T global_input_1 = Rand<T>();
      std::vector<T> global_input_1K = ::RandomVector<T>(1000);
      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(rand_val() % 2 == 1);
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

          encrypto::motion::ShareWrapper share_input_1 =
              motion_parties.at(party_id)->In<kAstra>(input_1, input_owner);
          encrypto::motion::ShareWrapper share_input_1K =
              motion_parties.at(party_id)->In<kAstra>(input_1K, input_owner);

          auto share_output_1 = share_input_1.Out(output_owner);
          auto share_output_1K = share_input_1K.Out(output_owner);

          motion_parties.at(party_id)->Run(1);

          EXPECT_EQ(share_output_1.As<T>(), global_input_1);
          EXPECT_EQ(share_output_1K.As<std::vector<T>>(), global_input_1K);
          
          motion_parties.at(party_id)->Finish();
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
  }
}

TEST(Astra, Addition_1_3_parties) {
  constexpr auto kAstra = encrypto::motion::MpcProtocol::kAstra;
  
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable) {
    using T = decltype(template_variable);
    const std::vector<T> kZeroV_1K(1000, 0);
    for (auto number_of_parties : {3u}) {
      std::size_t output_owner = kAll;
      std::vector<T> input_1 = ::RandomVector<T>(number_of_parties);
      std::vector<std::vector<T>> input_1K(number_of_parties);
      for (auto& v : input_1K) {
        v = ::RandomVector<T>(1000);
      }
      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(rand_val() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input_1; 
          std::vector<encrypto::motion::ShareWrapper> share_input_1K;
          for (auto j = 0u; j < number_of_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_input_1 = party_id == j ? input_1.at(j) : 0;
            const std::vector<T>& my_input_1K = party_id == j ? input_1K.at(j) : kZeroV_1K;

            share_input_1.push_back(motion_parties.at(party_id)->In<kAstra>(my_input_1, j));
            share_input_1K.push_back(
                motion_parties.at(party_id)->In<kAstra>(my_input_1K, j));
          }

          auto share_add_1 = share_input_1.at(0) + share_input_1.at(1);
          auto share_add_1K = share_input_1K.at(0) + share_input_1K.at(1);

          for (auto j = 2u; j < number_of_parties; ++j) {
            share_add_1 += share_input_1.at(j);
            share_add_1K += share_input_1K.at(j);
          }

          //auto share_output_1 = share_add_1.Out(output_owner);
          //auto share_output_1K = share_add_1K.Out(output_owner);

          auto share_output_1_all = share_add_1.Out();
          auto share_output_1K_all = share_add_1K.Out();

          motion_parties.at(party_id)->Run(1);
          
          /*
          if (party_id == output_owner) {
            T circuit_result_1 = share_output_1.As<T>();
            T expected_result_1 = SumReduction(input_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            
            const std::vector<T>& circuit_result_1K = share_output_1K.As<std::vector<T>>();
            const std::vector<T> expected_result_1K = std::move(RowSumReduction(input_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
            
          }
          */
          {
            T circuit_result_1 = share_output_1_all.As<T>();
            T expected_result_1 = SumReduction(input_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);
            
           
            const std::vector<T>& circuit_result_1K = share_output_1K_all.As<std::vector<T>>();
            const std::vector<T> expected_result_1K = std::move(RowSumReduction(input_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
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
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(Astra, Subtraction_1_3_parties) {
  constexpr auto kAstra = encrypto::motion::MpcProtocol::kAstra;
  
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable) {
    using T = decltype(template_variable);
    const std::vector<T> kZeroV_1K(1000, 0);
    for (auto number_of_parties : {3u}) {
      std::size_t output_owner = kAll;
      std::vector<T> input_1 = ::RandomVector<T>(number_of_parties);
      std::vector<std::vector<T>> input_1K(number_of_parties);
      for (auto& v : input_1K) {
        v = ::RandomVector<T>(1000);
      }
      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(rand_val() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_input_1, share_input_1K;
          for (auto j = 0u; j < number_of_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_input_1 = party_id == j ? input_1.at(j) : 0;
            const std::vector<T>& my_input_1K = party_id == j ? input_1K.at(j) : kZeroV_1K;

            share_input_1.push_back(motion_parties.at(party_id)->In<kAstra>(my_input_1, j));
            share_input_1K.push_back(
                motion_parties.at(party_id)->In<kAstra>(my_input_1K, j));
          }

          auto share_sub_1 = share_input_1.at(0) - share_input_1.at(1);
          auto share_sub_1K = share_input_1K.at(0) - share_input_1K.at(1);

          for (auto j = 2u; j < number_of_parties; ++j) {
            share_sub_1 -= share_input_1.at(j);
            share_sub_1K -= share_input_1K.at(j);
          }

          //auto share_output_1 = share_sub_1.Out(output_owner);
          //auto share_output_1K = share_sub_1K.Out(output_owner);

          auto share_output_1_all = share_sub_1.Out();
          auto share_output_1K_all = share_sub_1K.Out();

          motion_parties.at(party_id)->Run(1);

          /*
          if (party_id == output_owner) {
            T circuit_result_1 = share_output_1.As<T>();
            T expected_result_1 = SumReduction(input_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            
            const std::vector<T>& circuit_result_1K = share_output_1K.As<std::vector<T>>();
            const std::vector<T> expected_result_1K = std::move(RowSumReduction(input_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
            
          }
          */
          {
            T circuit_result_1 = share_output_1_all.As<T>();
            T expected_result_1 = SubReduction(input_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);
            
            
            const std::vector<T>& circuit_result_1K = share_output_1K_all.As<std::vector<T>>();
            const std::vector<T> expected_result_1K = std::move(RowSubReduction(input_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
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
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(Astra, Multiplication_1_3_parties) {
  constexpr auto kAstra = encrypto::motion::MpcProtocol::kAstra;
  std::srand(0);
  auto template_test = [](auto template_variable) {
    using T = decltype(template_variable);
    const std::vector<T> kZeroV_100(100, 0);
    for (auto number_of_parties : {3u}) {
      std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<T> input_1 = ::RandomVector<T>(number_of_parties);
      std::vector<std::vector<T>> input_100(number_of_parties);
      for (auto& v : input_100) {
        v = ::RandomVector<T>(100);
      }
      std::vector<PartyPointer> motion_parties(
          std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
      for (auto& party : motion_parties) {
        party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
        party->GetConfiguration()->SetOnlineAfterSetup(rand_val() % 2 == 1);
      }
      std::vector<std::future<void>> futures;
      for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
        futures.emplace_back(std::async(std::launch::async, [party_id, output_owner,
                                                             number_of_parties, &motion_parties,
                                                             input_1, input_100, kZeroV_100] {
          std::vector<encrypto::motion::ShareWrapper> share_input_1, share_input_100;
          for (auto j = 0u; j < number_of_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_input_1 = party_id == j ? input_1.at(j) : 0;
            const std::vector<T>& my_input_100 = party_id == j ? input_100.at(j) : kZeroV_100;

            share_input_1.push_back(motion_parties.at(party_id)->In<kAstra>(my_input_1, j));
            share_input_100.push_back(
                motion_parties.at(party_id)->In<kAstra>(my_input_100, j));
          }

          auto share_multiplication_1 = share_input_1.at(0) * share_input_1.at(1);
          auto share_multiplication_100 = share_input_100.at(0) * share_input_100.at(1);

          for (auto j = 2u; j < number_of_parties; ++j) {
            share_multiplication_1 *= share_input_1.at(j);
            share_multiplication_100 *= share_input_100.at(j);
          }

          //auto share_output_1 = share_multiplication_1.Out(output_owner);
          //auto share_output_1K = share_multiplication_100.Out(output_owner);

          auto share_output_1_all = share_multiplication_1.Out();
          auto share_output_100_all = share_multiplication_100.Out();

          motion_parties.at(party_id)->Run();
          
          /*
          if (party_id == output_owner) {
            T circuit_result_1 = share_output_1.As<T>();
            T expected_result_1 = MulReduction(input_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);
            
            const std::vector<T> circuit_result_100 = share_output_1K.As<std::vector<T>>();
            const std::vector<T> expected_result_100 = std::move(RowMulReduction(input_100));
            for (auto i = 0u; i < circuit_result_100.size(); ++i) {
              EXPECT_EQ(circuit_result_100.at(i), expected_result_100.at(i));
            }
            
          }
          */
          {
            T circuit_result_1 = share_output_1_all.As<T>();
            T expected_result_1 = MulReduction(input_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> circuit_result_100 = share_output_100_all.As<std::vector<T>>();
            const std::vector<T> expected_result_100 = std::move(RowMulReduction(input_100));
            for (auto i = 0u; i < circuit_result_100.size(); ++i) {
              EXPECT_EQ(circuit_result_100.at(i), expected_result_100.at(i));
            }
          }
          motion_parties.at(party_id)->Finish();
        }));
      }
      for (auto& f : futures) f.get();
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(Astra, DotProduct_1_3_parties) {
  constexpr auto kAstra = encrypto::motion::MpcProtocol::kAstra;
  constexpr auto kDimension = 4;
  std::srand(0);
  auto template_test = [](auto template_variable) {
    using T = decltype(template_variable);
    for (auto number_of_parties : {3u}) {
      std::size_t output_owner = std::rand() % number_of_parties;
      std::vector<std::vector<T>> input_1(number_of_parties);
      for(auto& v : input_1) {
        v = ::RandomVector<T>(kDimension);
      }
      std::vector<std::vector<T>> extra_input_1(number_of_parties - 2);
      for(auto& v : extra_input_1) {
        v = ::RandomVector<T>(kDimension - 1);
      }
      std::vector<PartyPointer> motion_parties(
          std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
      for (auto& party : motion_parties) {
        party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
        party->GetConfiguration()->SetOnlineAfterSetup(rand_val() % 2 == 1);
      }
      std::vector<std::future<void>> futures;
      for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
        futures.emplace_back(std::async(std::launch::async, [party_id, output_owner,
                                                             number_of_parties, &motion_parties,
                                                             input_1, extra_input_1] {
          std::vector<std::vector<encrypto::motion::ShareWrapper>> share_input_1(number_of_parties);
          for (auto i = 0u; i != number_of_parties; ++i) {
            std::vector<T> const& my_input_1 = input_1.at(i);
            for(auto j = 0u; j != kDimension; ++j) {
              share_input_1.at(i).push_back(motion_parties.at(party_id)->In<kAstra>(my_input_1.at(j), i));
            }
          }

          auto share_dot_product_1 = encrypto::motion::DotProduct(share_input_1.at(0), share_input_1.at(1));

          for (auto j = 2u; j < number_of_parties; ++j) {
            std::vector<encrypto::motion::ShareWrapper> d;
            d.push_back(share_dot_product_1);
            for(auto e : extra_input_1.at(j - 2)) {
              d.push_back(motion_parties.at(party_id)->In<kAstra>(e, 0));
            }
            share_dot_product_1 = encrypto::motion::DotProduct(d, share_input_1.at(j));
          }


          auto share_output_1_all = share_dot_product_1.Out();

          motion_parties.at(party_id)->Run();
          
          {
            T circuit_result_1 = share_output_1_all.As<T>();
            auto dot_product = [](std::vector<T> const& a, std::vector<T> const& b) {
              T result = 0;
              for(auto i = 0u; i != a.size(); ++i) {
                result += a[i] * b[i];
              }
              return result;
            };
            T expected_result_1 = dot_product(input_1.at(0), input_1.at(1));
            for(auto j = 2u; j < number_of_parties; ++j) {
              std::vector<T> d;
              d.push_back(expected_result_1);
              for(auto e : extra_input_1.at(j - 2)) {
                d.push_back(e);
              }
              expected_result_1 = dot_product(d, input_1.at(j));
            }
            EXPECT_EQ(circuit_result_1, expected_result_1);
          }
          motion_parties.at(party_id)->Finish();
        }));
      }
      for (auto& f : futures) f.get();
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}