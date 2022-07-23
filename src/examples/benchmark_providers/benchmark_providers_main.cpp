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
#include "common/benchmark_providers.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/typedefs.h"

namespace program_options = boost::program_options;

bool CheckPartyArgumentSyntax(const std::string& party_arguments);

std::tuple<program_options::variables_map, bool, bool> ParseProgramOptions(int ac, char* av[]);

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options);

int main(int ac, char* av[]) {
  auto [user_options, help_flag, ots_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) EXIT_SUCCESS;
  const auto number_of_repetitions{user_options["repetitions"].as<std::size_t>()};
  const auto batch_size{user_options["batch-size"].as<std::size_t>()};

  struct Combination {
    Combination(Provider provider, std::size_t bit_size, std::size_t batch_size)
        : provider_(provider), bit_size_(bit_size), batch_size_(batch_size) {}
    Provider provider_;
    std::size_t bit_size_;
    std::size_t batch_size_;
  };

  // clang-format off
  std::vector<Combination> combinations = {
    {kAmt, 8, batch_size},
    {kAmt, 16, batch_size},
    {kAmt, 32, batch_size},
    {kAmt, 64, batch_size},
    {kBmt, 1, batch_size},
    {kSb, 8, batch_size},
    {kSb, 16, batch_size},
    {kSb, 32, batch_size},
    {kSb, 64, batch_size},
    {kSp, 8, batch_size},
    {kSp, 16, batch_size},
    {kSp, 32, batch_size},
    {kSp, 64, batch_size}
  };

  std::vector<Combination> combinations_ots = {
    {kGOt, 1, batch_size},
    {kGOt, 128, batch_size},
    {kXcOt, 1, batch_size},
    {kXcOt, 128, batch_size},
    {kAcOt, 8, batch_size},
    {kAcOt, 16, batch_size},
    {kAcOt, 32, batch_size},
    {kAcOt, 64, batch_size},
    {kAcOt, 128, batch_size},
    {kROt, 128, batch_size}
  };
  // clang-format on

  auto chosen_combinations = ots_flag ? combinations_ots : combinations;
  for (const auto combination : chosen_combinations) {
    encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
    encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
    for (std::size_t i = 0; i < number_of_repetitions; ++i) {
      encrypto::motion::PartyPointer party{CreateParty(user_options)};
      auto statistics = BenchmarkProvider(party, combination.batch_size_, combination.provider_,
                                          combination.bit_size_);
      accumulated_statistics.Add(statistics);
      auto communication_statistics =
          party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
      accumulated_communication_statistics.Add(communication_statistics);
    }
    std::cout << encrypto::motion::PrintStatistics(
        fmt::format("Provider {} bit size {} batch size {}", to_string(combination.provider_),
                    combination.bit_size_, combination.batch_size_),
        accumulated_statistics, accumulated_communication_statistics);
  }
  return EXIT_SUCCESS;
}

const std::regex kPartyArgumentRegex(
    "(\\d+),(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& party_arguments) {
  // other party's id, IP address, and port
  return std::regex_match(party_arguments, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_arguments) {
  std::smatch match;
  std::regex_match(party_arguments, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

// <variables map, help flag>
std::tuple<program_options::variables_map, bool, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view kConfigFileMessage =
      "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;
  bool print, help, ots;
  boost::program_options::options_description description("Allowed options");
  // clang-format off
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("batch-size", program_options::value<std::size_t>()->default_value(1000000), "number of elements in the batch")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("online-after-setup", program_options::value<bool>()->default_value(true), "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)")
      ("repetitions", program_options::value<std::size_t>()->default_value(1), "number of repetitions")
      ("ots,o", program_options::bool_switch(&ots)->default_value(false),"test OTs, otherwise all other providers");
  // clang-format on

  program_options::variables_map user_options;

  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);

  // argument help or no arguments (at least a configuration file is expected)
  if (help) {
    std::cout << description << "\n";
    return std::make_tuple<program_options::variables_map, bool, bool>({}, true, false);
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
    for (auto& p : other_parties) {
      if (CheckPartyArgumentSyntax(p)) {
        if (print) parties.append(" " + p);
      } else {
        throw std::runtime_error("Incorrect party argument syntax " + p);
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
  return std::make_tuple(user_options, help, ots);
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
