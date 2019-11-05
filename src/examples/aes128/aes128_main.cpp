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

#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/party.h"
#include "common/aes128.h"

namespace po = boost::program_options;

bool CheckPartyArgumentSyntax(const std::string& p);

std::pair<po::variables_map, bool> ParseProgramOptions(int ac, char* av[]);

MOTION::PartyPtr CreateParty(const po::variables_map& vm);

int main(int ac, char* av[]) {
  auto [vm, help_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) return 1;

  MOTION::PartyPtr party{CreateParty(vm)};
  // establish communication channels with other parties
  party->Connect();

  EvaluateProtocol(party);
  return 0;
}

bool CheckPartyArgumentSyntax(const std::string& p) {
  // other party's id, IP address, and port
  const std::regex re("\\d+,\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3},\\d{1,5}");
  return std::regex_match(p, re);
}

// <variables map, help flag>
std::pair<po::variables_map, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view config_file_msg =
      "config file, other arguments will overwrite the parameters read from the config file"sv;
  bool print, help;
  boost::program_options::options_description desc("Allowed options");
  // clang-format off
  desc.add_options()
      ("help,h", po::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-config,p", po::bool_switch(&print)->default_value(false), "print config")
      ("config-file,f", po::value<std::string>(), config_file_msg.data())
      ("my-id", po::value<std::size_t>(), "my party id")
      ("other-parties", po::value<std::vector<std::string>>()->multitoken(), "(other party id, IP, port, my role), e.g., --other-parties 1,127.0.0.1,7777");
  // clang-format on

  po::variables_map vm;

  po::store(po::parse_command_line(ac, av, desc), vm);
  po::notify(vm);

  // argument help or no arguments (at least a config file is expected)
  if (vm.count("help") || ac == 1) {
    std::cout << desc << "\n";
    return std::make_pair<po::variables_map, bool>({}, true);
  }

  // read config file
  if (vm.count("config-file")) {
    std::ifstream ifs(vm["config-file"].as<std::string>().c_str());
    po::variables_map vm_config_file;
    po::store(po::parse_config_file(ifs, desc), vm);
    po::notify(vm);
  }

  // print parsed parameters
  if (vm.count("my-id")) {
    if (print) std::cout << "My id " << vm["my-id"].as<std::size_t>() << std::endl;
  } else
    throw std::runtime_error("My id is not set but required");

  if (vm.count("other-parties")) {
    const std::vector<std::string> other_parties{
        vm["other-parties"].as<std::vector<std::string>>()};
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

  return std::make_pair(vm, help);
}

MOTION::PartyPtr CreateParty(const po::variables_map& vm) {
  const auto parties_str{vm["other-parties"].as<const std::vector<std::string>>()};
  const auto num_parties{parties_str.size() + 1};
  const auto my_id{vm["my_id"].as<std::size_t>()};
  if (my_id >= num_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
        my_id, num_parties));
  }

  // create communication contexts for other parties
  std::vector<MOTION::Communication::ContextPtr> contexts(num_parties, nullptr);
  for (const auto& party_str : parties_str) {
    const auto comma1{party_str.find_first_of(',')};
    const auto comma2{party_str.find_last_of(',')};

    const auto other_id{boost::lexical_cast<std::size_t>(party_str.substr(0, comma1))};
    if (other_id >= num_parties) {
      throw std::runtime_error(
          fmt::format("Other party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      other_id, num_parties));
    } else if (contexts.at(other_id)) {
      throw std::runtime_error(
          fmt::format("Other party ids must be unique, id {} is not unique", other_id));
    }

    const auto role{other_id < my_id ? MOTION::Role::Client : MOTION::Role::Server};

    const std::uint16_t port{
        boost::lexical_cast<std::uint16_t>(party_str.substr(comma2, party_str.size()))};
    const std::string ip{party_str.substr(comma1, comma2)};

    contexts.emplace(contexts.begin() + other_id, std::make_shared<MOTION::Communication::Context>(
                                                      "127.0.0.1", port, role, other_id));
  }
  // create config for my party
  auto config{std::make_shared<MOTION::Configuration>(std::move(contexts), my_id)};
  // disable logging if the corresponding flag was set
  const auto logging{!vm.count("disable-logging")};
  config->SetLoggingEnabled(logging);
  // create party object using the given config
  return std::make_unique<MOTION::Party>(config);
}