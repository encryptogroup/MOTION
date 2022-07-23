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
#include "common/benchmark_primitive_operations.h"
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
              encrypto::motion::PrimitiveOperationType operation_type, std::size_t number_of_simd)
      : bit_size(bit_size),
        protocol(protocol),
        operation_type(operation_type),
        number_of_simd(number_of_simd) {}

  std::size_t bit_size{0};
  encrypto::motion::MpcProtocol protocol{kIllegalProtocol};
  encrypto::motion::PrimitiveOperationType operation_type{kIllegalOperationType};
  std::size_t number_of_simd{0};
};

std::vector<Combination> GenerateAllCombinations() {
  using T = encrypto::motion::PrimitiveOperationType;

  const std::array kArithmeticBitSizes = {8, 16, 32, 64};
  const std::array kBooleanBitSizes = {1000};
  const std::array kNumbersOfSimd = {1000};
  const std::array kBooleanOperationTypes = {T::kIn, T::kOut, T::kXor, T::kAnd, T::kMux, T::kInv};
  const std::array kArithmeticOperationTypes = {T::kIn, T::kOut, T::kAdd, T::kMul};

  std::vector<Combination> combinations;

  for (const auto bit_size : kBooleanBitSizes) {
    for (const auto number_of_simd : kNumbersOfSimd) {
      for (const auto operation_type : kBooleanOperationTypes) {
        combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kBooleanGmw,
                                  operation_type, number_of_simd);
        combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kBmr, operation_type,
                                  number_of_simd);
      }

      combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kBooleanGmw, T::kB2Y,
                                number_of_simd);
      combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kBmr, T::kY2B,
                                number_of_simd);
    }
  }

  for (const auto bit_size : kArithmeticBitSizes) {
    for (const auto number_of_simd : kNumbersOfSimd) {
      for (const auto operation_type : kArithmeticOperationTypes) {
        combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kArithmeticGmw,
                                  operation_type, number_of_simd);
      }
      combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kBooleanGmw, T::kB2A,
                                number_of_simd);
      combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kBmr, T::kY2A,
                                number_of_simd);
      combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kArithmeticGmw, T::kA2B,
                                number_of_simd);
      combinations.emplace_back(bit_size, encrypto::motion::MpcProtocol::kArithmeticGmw, T::kA2Y,
                                number_of_simd);
    }
  }
  return combinations;
}

int main(int ac, char* av[]) {
  auto [user_options, help_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) return EXIT_SUCCESS;

  const auto number_of_repititions{user_options["repetitions"].as<std::size_t>()};

  std::vector<Combination> combinations;

  // TODO: add custom combination instead of generating all of them if needed

  combinations = GenerateAllCombinations();

  for (const auto combination : combinations) {
    encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
    encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
    for (std::size_t i = 0; i < number_of_repititions; ++i) {
      encrypto::motion::PartyPointer party{CreateParty(user_options)};
      // establish communication channels with other parties
      auto statistics = EvaluateProtocol(party, combination.number_of_simd, combination.bit_size,
                                         combination.protocol, combination.operation_type);
      accumulated_statistics.Add(statistics);
      auto communcation_statistics =
          party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
      accumulated_communication_statistics.Add(communcation_statistics);
    }
    std::cout << encrypto::motion::PrintStatistics(
        fmt::format("Protocol {} operation {} bit size {} SIMD {}",
                    encrypto::motion::to_string(combination.protocol),
                    encrypto::motion::to_string(combination.operation_type), combination.bit_size,
                    combination.number_of_simd),
        accumulated_statistics, accumulated_communication_statistics);
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
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("online-after-setup", program_options::value<bool>()->default_value(true), "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)")
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
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
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
