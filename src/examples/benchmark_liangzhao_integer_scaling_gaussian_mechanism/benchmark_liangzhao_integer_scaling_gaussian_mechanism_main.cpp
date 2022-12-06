// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include <cmath>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/party.h"
#include "common/benchmark_liangzhao_integer_scaling_gaussian_mechanism.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/typedefs.h"

namespace program_options = boost::program_options;

bool CheckPartyArgumentSyntax(const std::string& party_argument);

std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]);

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options);

constexpr std::size_t kIllegalProtocol{100}, kIllegalOperationType{100};

struct Combination {
  Combination(std::size_t bit_size, encrypto::motion::MpcProtocol protocol,
              encrypto::motion::DPMechanismType operation_type, std::size_t number_of_simd,
              double failure_probability)
      : bit_size_(bit_size),
        protocol_(protocol),
        operation_type_(operation_type),
        number_of_simd_(number_of_simd),
        failure_probability_(failure_probability) {}

  std::size_t bit_size_{0};
  encrypto::motion::MpcProtocol protocol_{kIllegalProtocol};
  encrypto::motion::DPMechanismType operation_type_{kIllegalOperationType};
  std::size_t number_of_simd_{0};
  double failure_probability_{std::exp2l(-40)};
};

std::vector<Combination> GenerateAllCombinations() {
  using T = encrypto::motion::DPMechanismType;

  // const std::array kBitSizes = {64};
  // const std::array kNumbersOfSimd = {1, 10};

  const std::array kDPMechanismType = {
      T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
      T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized,
      T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
      T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
  };

  std::vector<Combination> combinations;
  // double failure_probability_pow2_neg_35 = std::exp2l(-35.0);
  double failure_probability_pow2_neg_40 = std::exp2l(-40.0);

  std::size_t batch_size = 1;

  // std::size_t num_of_parties = 2;
  // std::size_t num_of_parties = 3;
  std::size_t num_of_parties = 5;
  // bool benchmark_gc = true;
  bool benchmark_gc = false;
  bool benchmark_boolean_gmw = true;
  // bool benchmark_boolean_gmw = false;

  if (benchmark_gc && num_of_parties == 2) {
    // ================================================
    // ! Garbled Circuit
    batch_size = 1;

    // no huge improvement
    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(
        64, encrypto::motion::MpcProtocol::kGarbledCircuit,
        T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
        failure_probability_pow2_neg_40);

    // no huge improvement
    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
                              T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
                              batch_size, failure_probability_pow2_neg_40);

    // ================================================
    // ! Garbled Circuit
    batch_size = 5;

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(
        64, encrypto::motion::MpcProtocol::kGarbledCircuit,
        T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
        failure_probability_pow2_neg_40);

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
                              T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
                              batch_size, failure_probability_pow2_neg_40);

    // ================================================
    // ! Garbled Circuit
    batch_size = 10;

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(
        64, encrypto::motion::MpcProtocol::kGarbledCircuit,
        T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
        failure_probability_pow2_neg_40);

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
                              T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
                              batch_size, failure_probability_pow2_neg_40);

    // ================================================
    // ! Garbled Circuit
    batch_size = 30;  // no overflow

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(
        64, encrypto::motion::MpcProtocol::kGarbledCircuit,
        T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
        failure_probability_pow2_neg_40);

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(64, encrypto::motion::MpcProtocol::kGarbledCircuit,
                              T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
                              batch_size, failure_probability_pow2_neg_40);
  }

  if (benchmark_boolean_gmw && num_of_parties == 3) {
    // ================================================
    // ! BooleanGMW
    batch_size = 1;

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(
        64, encrypto::motion::MpcProtocol::kBooleanGmw,
        T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
        failure_probability_pow2_neg_40);

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
                              T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
                              batch_size, failure_probability_pow2_neg_40);

    // ================================================
    // ! BooleanGMW
    batch_size = 4;  // no overflow (almost overflow)

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    // combinations.emplace_back(
    //     64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //     T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
    //     failure_probability_pow2_neg_40);

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
    //                           batch_size, failure_probability_pow2_neg_40);
  }

  if (benchmark_boolean_gmw && num_of_parties == 5) {
    // ================================================
    // ! BooleanGMW
    batch_size = 1;

    // only for debugging
    batch_size = 4; 

    // on huge improvement
    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(
        64, encrypto::motion::MpcProtocol::kBooleanGmw,
        T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
        failure_probability_pow2_neg_40);

    // on huge improvement
    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
                              T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
                              batch_size, failure_probability_pow2_neg_40);
    // ================================================
    // ! BooleanGMW
    batch_size = 4;  // ? if overflow

    // on huge improvement
    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(
        64, encrypto::motion::MpcProtocol::kBooleanGmw,
        T::kIntegerScalingGaussianMechanism_FLGaussian_noise_generation_optimized, batch_size,
        failure_probability_pow2_neg_40);

    // on huge improvement
    // combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
    //                           T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_naive,
    //                           batch_size, failure_probability_pow2_neg_40);

    combinations.emplace_back(64, encrypto::motion::MpcProtocol::kBooleanGmw,
                              T::kIntegerScalingGaussianMechanism_FLGaussian_perturbation_optimized,
                              batch_size, failure_probability_pow2_neg_40);
  }

  // ================================================
  return combinations;
}

int main(int ac, char* av[]) {
  auto [user_options, help_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) return EXIT_SUCCESS;

  const auto number_of_repetitions{user_options["repetitions"].as<std::size_t>()};

  std::vector<Combination> combinations;

  // TODO: add custom combination instead of generating all of them if needed

  combinations = GenerateAllCombinations();

  // // added by Liang Zhao
  // std::string party_id = std::to_string(user_options.at("my-id").as<std::size_t>());
  // const std::string CSV_filename =
  //     "../../src/examples/benchmark_liangzhao_discrete_laplace_discrete_gaussian_mechanism/"
  //     "benchmark_liangzhao_discrete_laplace_discrete_gaussian_mechanism_P" +
  //     party_id + ".csv";
  // encrypto::motion::CreateCsvFile(CSV_filename);

  // const std::string txt_filename =
  //     "../../src/examples/benchmark_liangzhao_discrete_laplace_discrete_gaussian_mechanism/"
  //     "benchmark_liangzhao_discrete_laplace_discrete_gaussian_mechanism_P" +
  //     party_id + ".txt";
  // encrypto::motion::CreateTxtFile(txt_filename);

  for (const auto combination : combinations) {
    encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
    encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
    for (std::size_t i = 0; i < number_of_repetitions; ++i) {
      encrypto::motion::PartyPointer party{CreateParty(user_options)};
      // establish communication channels with other parties
      auto statistics = EvaluateProtocol(party, combination.number_of_simd_, combination.bit_size_,
                                         combination.protocol_, combination.operation_type_,
                                         combination.failure_probability_);
      accumulated_statistics.Add(statistics);
      auto communication_statistics =
          party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
      accumulated_communication_statistics.Add(communication_statistics);
    }
    // std::cout << fmt::format(encrypto::motion::to_string(combination.protocol_),
    //                          encrypto::motion::to_string(combination.operation_type_),
    //                          combination.bit_size_, combination.number_of_simd_);
    std::cout << encrypto::motion::PrintStatistics(
        fmt::format("Protocol {} operation {} bit size {} SIMD {}",
                    encrypto::motion::to_string(combination.protocol_),
                    encrypto::motion::to_string(combination.operation_type_), combination.bit_size_,
                    combination.number_of_simd_),
        accumulated_statistics, accumulated_communication_statistics);

    // // added by Liang Zhao
    // encrypto::motion::WriteToTxt(
    //     txt_filename, fmt::format(encrypto::motion::to_string(combination.protocol_),
    //                               encrypto::motion::to_string(combination.operation_type_),
    //                               combination.bit_size_, combination.number_of_simd_));

    // encrypto::motion::WriteToTxt(
    //     txt_filename, encrypto::motion::PrintStatistics(
    //                       fmt::format("Protocol {} operation {} bit size {} SIMD {}",
    //                                   encrypto::motion::to_string(combination.protocol_),
    //                                   encrypto::motion::to_string(combination.operation_type_),
    //                                   combination.bit_size_, combination.number_of_simd_),
    //                       accumulated_statistics, accumulated_communication_statistics));

    // // added by Liang Zhao
    // encrypto::motion::WriteToCsv(
    //     fmt::format("{} {}-bit SIMD-{}",
    //     encrypto::motion::to_string(combination.operation_type_),
    //                 combination.bit_size_, combination.number_of_simd_),
    //     CSV_filename, accumulated_statistics, accumulated_communication_statistics);
  }
  return EXIT_SUCCESS;
}

const std::regex kPartyArgumentRegex(
    "(\\d+),(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& party_argument) {
  // other party's id, IP address, and port
  return std::regex_match(party_argument, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_argument) {
  std::smatch match;
  std::regex_match(party_argument, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

// <variables map, help flag>
std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view kConfigFileMessage =
      "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;
  bool print, help;
  boost::program_options::options_description description("Allowed options");
  // clang-format off
    description.add_options()
            ("help,h", program_options::bool_switch(&help)->default_value(false), "produce help message")
            ("disable-logging,l", "disable logging to file")
            ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
            ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
            ("my-id", program_options::value<std::size_t>(), "my party id")
            ("parties", program_options::value<std::vector<std::string>>()->multitoken(),
             "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
            ("online-after-setup", program_options::value<bool>()->default_value(true),
             "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)")
            ("repetitions", program_options::value<std::size_t>()->default_value(1), "number of repetitions");
  // clang-format on

  program_options::variables_map user_options;

  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);

  // argument help or no arguments (at least a configuration file is expected)
  if (help) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, bool>({}, true);
  }

  // read configuration file
  if (user_options.count("configuration-file")) {
    std::ifstream ifs(user_options["configuration-file"].as<std::string>().c_str());
    program_options::variables_map user_option_config_file;
    program_options::store(program_options::parse_config_file(ifs, description), user_options);
    program_options::notify(user_options);
  }

  // print parsed parameters
  if (user_options.count("my-id")) {
    if (print) std::cout << "My id " << user_options["my-id"].as<std::size_t>() << std::endl;
  } else
    throw std::runtime_error("My id is not set but required");

  if (user_options.count("parties")) {
    const std::vector<std::string> other_parties{
        user_options["parties"].as<std::vector<std::string>>()};
    std::string parties("Other parties: ");
    for (auto& party : other_parties) {
      if (CheckPartyArgumentSyntax(party)) {
        if (print) parties.append(" " + party);
      } else {
        throw std::runtime_error("Incorrect party argument syntax " + party);
      }
    }
    if (print) std::cout << parties << std::endl;
  } else
    throw std::runtime_error("Other parties' information is not set but required");

  if (print) {
    std::cout << "Number of SIMD AES evaluations: " << user_options["num-simd"].as<std::size_t>()
              << std::endl;

    std::cout << "MPC Protocol: " << user_options["protocol"].as<std::string>() << std::endl;
  }
  return std::make_pair(user_options, help);
}

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options) {
  const auto parties_string{user_options["parties"].as<const std::vector<std::string>>()};
  const auto number_of_parties{parties_string.size()};
  const auto my_id{user_options["my-id"].as<std::size_t>()};
  if (my_id >= number_of_parties) {
    throw std::runtime_error(
        fmt::format("My id needs to be in the range [0, #parties - 1], current my id is {} and "
                    "#parties is {}",
                    my_id, number_of_parties));
  }

  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);

  for (const auto& party_string : parties_string) {
    const auto [party_id, host, port] = ParsePartyArgument(party_string);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(
          fmt::format("Party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }
  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));
  auto configuration = party->GetConfiguration();
  // disable logging if the corresponding flag was set
  const auto logging{!user_options.count("disable-logging")};
  configuration->SetLoggingEnabled(logging);
  configuration->SetOnlineAfterSetup(user_options["online-after-setup"].as<bool>());
  return party;
}
