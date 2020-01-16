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

#include "algorithm_description.h"

#include <fstream>
#include <regex>
#include <sstream>

#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <fmt/format.h>

namespace ENCRYPTO {

AlgorithmDescription AlgorithmDescription::FromBristol(const std::string& path) {
  std::ifstream fs(path);
  return FromBristol(fs);
}

AlgorithmDescription AlgorithmDescription::FromBristol(std::string&& path) {
  std::ifstream fs(path);
  return FromBristol(fs);
}

//
// Bristol format
// 49 65            *** total # of gates, total # of wires
// 8 8 8            *** # input wires parent a, # input wires parent b, # of output wires
//                  *** empty line
// *** below, only gate-related infos:
// *** # of input shares (bundled wires, i.e., XOR has 2 inputs, INV 1, and MUX 3),
// *** # of outputs,
// *** input wire ids (1--many)
// *** output wire ids (usually 1)
// *** gate type
// 2 1 0 8 57 XOR
// 2 1 1 9 16 XOR   ***
// 2 1 0 8 17 AND   ***
// ...
//

AlgorithmDescription AlgorithmDescription::FromBristol(std::ifstream& stream) {
  AlgorithmDescription algo;
  assert(stream.is_open());
  assert(stream.good());
  stream >> algo.n_gates_ >> algo.n_wires_;

  std::vector<std::string> line_v;
  std::string str;
  std::getline(stream, str);  // skip \n at the end of the first line
  // second line
  {
    std::string second_line;
    std::getline(stream, second_line);
    std::stringstream ss(second_line);
    while (std::getline(ss, str, ' ')) {
      line_v.emplace_back(std::move(str));
      str.clear();
    }
    algo.n_input_wires_parent_a_ = std::stoull(line_v.at(0));
    if (line_v.size() == 2) {
      algo.n_output_wires_ = std::stoull(line_v.at(1));
    } else if (line_v.size() == 3) {
      algo.n_input_wires_parent_b_ = std::stoull(line_v.at(1));
      algo.n_output_wires_ = std::stoull(line_v.at(2));
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " + std::to_string(line_v.size()) + "\n"));
    }
    str.clear();
    line_v.clear();
  }

  std::getline(stream, str);
  assert(str.empty());

  // read line
  while (std::getline(stream, str)) {
    std::stringstream ss(str);
    // split line
    while (std::getline(ss, str, ' ')) {
      line_v.emplace_back(std::move(str));
    }

    if (line_v.empty()) continue;
    const auto& type = line_v.at(line_v.size() - 1);
    PrimitiveOperation op;
    if (type == std::string("XOR") || type == std::string("AND") || type == std::string("ADD") ||
        type == std::string("MUL") || type == std::string("OR")) {
      assert(line_v.size() == 6);
      if (type == std::string("XOR"))
        op.type_ = PrimitiveOperationType::XOR;
      else if (type == std::string("AND"))
        op.type_ = PrimitiveOperationType::AND;
      else if (type == std::string("ADD"))
        op.type_ = PrimitiveOperationType::ADD;
      else if (type == std::string("MUL"))
        op.type_ = PrimitiveOperationType::MUL;
      else if (type == std::string("OR"))
        op.type_ = PrimitiveOperationType::OR;
      op.parent_a_ = std::stoull(line_v.at(2));
      op.parent_b_ = std::stoull(line_v.at(3));
      op.output_wire_ = std::stoull(line_v.at(4));
    } else if (type == std::string("MUX")) {
      assert(line_v.size() == 7);
      op.type_ = PrimitiveOperationType::MUX;
      op.parent_a_ = std::stoull(line_v.at(2));
      op.parent_b_ = std::stoull(line_v.at(3));
      op.selection_bit_ = std::stoull(line_v.at(4));
      op.output_wire_ = std::stoull(line_v.at(5));
    } else if (type == std::string("INV")) {
      assert(line_v.size() == 5);
      op.type_ = PrimitiveOperationType::INV;
      op.parent_a_ = std::stoull(line_v.at(2));
      op.output_wire_ = std::stoull(line_v.at(3));
    } else {
      throw std::runtime_error("Unknown operation type: " + line_v.at(line_v.size() - 1) + "\n");
    }
    algo.gates_.emplace_back(op);
    str.clear();
    line_v.clear();
  }
  return algo;
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(const std::string& path) {
  std::ifstream fs(path);
  return FromBristolFashion(fs);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::string&& path) {
  std::ifstream fs(path);
  return FromBristolFashion(fs);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::ifstream& stream) {
  AlgorithmDescription algo;
  assert(stream.is_open());
  assert(stream.good());

  const static std::regex line_two_numbers_re("^\\s*(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex line_three_numbers_re("^\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex line_gate_re("^\\s*(1|2)\\s+(1)\\s+(\\d+)\\s+(\\d+\\s+)?(\\d+)\\s+(XOR|AND|INV)\\s*$");
  const static std::regex line_whitespace_re("^\\s*$");

  std::string line;
  std::smatch match;

  // first line
  std::getline(stream, line);
  if (!std::regex_match(line, match, line_two_numbers_re)) {
    throw std::runtime_error("Cannot parse Bristol Fashion file at line 1");
  }
  algo.n_gates_ = boost::lexical_cast<std::size_t>(match[1]);
  algo.n_wires_ = boost::lexical_cast<std::size_t>(match[2]);

  // second line
  std::getline(stream, line);
  if (std::regex_match(line, match, line_two_numbers_re)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algo.n_input_wires_parent_a_ = boost::lexical_cast<std::size_t>(match[2]);
  } else if (std::regex_match(line, match, line_three_numbers_re)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 2) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algo.n_input_wires_parent_a_ = boost::lexical_cast<std::size_t>(match[2]);
    algo.n_input_wires_parent_b_ = boost::lexical_cast<std::size_t>(match[3]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 2 (maybe unsupported number of input values)");
  }

  // third line
  std::getline(stream, line);
  if (std::regex_match(line, match, line_two_numbers_re)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 3");
    }
    algo.n_output_wires_ = boost::lexical_cast<std::size_t>(match[2]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 3 (maybe unsupported number of output values)");
  }

  // consume empty line
  std::getline(stream, line);
  assert(line.empty());

  std::size_t line_no = 4;

  // read gates
  while (std::getline(stream, line)) {
    ++line_no;
    if (line.empty() || std::regex_match(line, line_whitespace_re)) {
      continue;
    }

    if (!std::regex_match(line, match, line_gate_re)) {
      throw std::runtime_error(
          fmt::format("Cannot parse Bristol Fashion file at line {}", line_no));
    }

    using namespace std::string_literals;

    auto num_inputs = boost::lexical_cast<std::size_t>(match[1]);
    const auto& operation = match[6];
    PrimitiveOperation op;

    if (operation == "XOR"s) {
      if (num_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_no));
      }
      op.type_ = PrimitiveOperationType::XOR;
    } else if (operation == "AND"s) {
      if (num_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_no));
      }
      op.type_ = PrimitiveOperationType::AND;
    } else if (operation == "INV"s) {
      if (num_inputs != 1) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_no));
      }
      op.type_ = PrimitiveOperationType::INV;
    }
    op.output_wire_ = boost::lexical_cast<std::size_t>(match[5]);
    op.parent_a_ = boost::lexical_cast<std::size_t>(match[3]);
    if (num_inputs == 2) {
      std::string input_b = match[4];
      boost::algorithm::trim(input_b);
      op.parent_b_ = boost::lexical_cast<std::size_t>(input_b);
    }
    algo.gates_.emplace_back(std::move(op));
  }

  return algo;
}

AlgorithmDescription AlgorithmDescription::FromABY(const std::string& path) {
  std::ifstream fs(path);
  return FromBristol(fs);
}

AlgorithmDescription AlgorithmDescription::FromABY(std::string&& path) {
  std::ifstream fs(path);
  return FromBristol(fs);
}

AlgorithmDescription AlgorithmDescription::FromABY(std::ifstream& stream) {
  AlgorithmDescription algo;
  assert(stream.is_open());
  assert(stream.good());
  std::string str;
  int INVALID_VALUE = 999999999;
  int const_0 = INVALID_VALUE, const_1 = INVALID_VALUE;
  do {
    std::getline(stream, str);
    switch (str[0]) {
      case '#':  // comment
        break;
      case '\n':  // empty line
        break;
      case '0':  // constant 0
        const_0 = std::stoi(str.substr(1, str.size() - 1));
        break;
      case '1':  // constant 1
        const_1 = std::stoi(str.substr(1, str.size() - 1));
        break;
      case 'C':  // client's inputs
      {
        std::stringstream ss(str);
        std::string val;
        std::getline(ss, val, ' ');
        assert(val == "C");
        while (std::getline(ss, val, ' ')) ++algo.n_input_wires_parent_a_;
        break;
      }
      case 'S':  // server's inputs
      {
        std::stringstream ss(str);
        std::string val;
        std::getline(ss, val, ' ');
        assert(val == "S");
        while (std::getline(ss, val, ' ')) ++algo.n_input_wires_parent_a_;
        break;
      }
      default:
        throw std::logic_error(std::string("Invalid first symbol ") + str[0]);
    }
  } while (str != "#Gates");
  std::vector<std::string> line_v;

  assert(const_0 != INVALID_VALUE);
  assert(const_1 != INVALID_VALUE);

  // read gates
  do {
    std::getline(stream, str);
    if(str.size() <= 1) continue;
    switch(str[0]){
      case 'A': // AND gate, `A 101 102 103` denotes 103 = 101 AND 102
        // AND with const_1 is the same gate
        // AND with const_0 is illegal for now
        break;
      case 'I': // INV gate, `I 101 102` denotes that 102 = NOT 101
        break;
      case 'M': // MUX gate, `M 101 102 103 104` denotes 104 = 103 ? 102 : 101
        break;
      case 'X': // XOR gate, `X 101 102 103` denotes 103 = 101 XOR 102
      // XOR with const_1 is an INV gate
      // XOR with const_0 is the same gate
        break;
      default:
        throw std::logic_error(std::string("Invalid first symbol ") + str[0]);
    }
    std::stringstream ss(str);
    while (std::getline(ss, str, ' ')) {
      line_v.emplace_back(std::move(str));
      str.clear();
    }
    algo.n_input_wires_parent_a_ = std::stoull(line_v.at(0));
    if (line_v.size() == 2) {
      algo.n_output_wires_ = std::stoull(line_v.at(1));
    } else if (line_v.size() == 3) {
      algo.n_input_wires_parent_b_ = std::stoull(line_v.at(1));
      algo.n_output_wires_ = std::stoull(line_v.at(2));
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " + std::to_string(line_v.size()) + "\n"));
    }
    str.clear();
    line_v.clear();
  } while (str != "\n");

  assert(str.empty());

  // read output IDs
  while (std::getline(stream, str)) {
    std::stringstream ss(str);
    // split line
    while (std::getline(ss, str, ' ')) {
      line_v.emplace_back(std::move(str));
    }

    if (line_v.empty()) continue;
    const auto& type = line_v.at(line_v.size() - 1);
    PrimitiveOperation op;
    if (type == std::string("XOR") || type == std::string("AND") || type == std::string("ADD") ||
        type == std::string("MUL") || type == std::string("OR")) {
      assert(line_v.size() == 6);
      if (type == std::string("XOR"))
        op.type_ = PrimitiveOperationType::XOR;
      else if (type == std::string("AND"))
        op.type_ = PrimitiveOperationType::AND;
      else if (type == std::string("ADD"))
        op.type_ = PrimitiveOperationType::ADD;
      else if (type == std::string("MUL"))
        op.type_ = PrimitiveOperationType::MUL;
      else if (type == std::string("OR"))
        op.type_ = PrimitiveOperationType::OR;
      op.parent_a_ = std::stoull(line_v.at(2));
      op.parent_b_ = std::stoull(line_v.at(3));
      op.output_wire_ = std::stoull(line_v.at(4));
    } else if (type == std::string("MUX")) {
      assert(line_v.size() == 7);
      op.type_ = PrimitiveOperationType::MUX;
      op.parent_a_ = std::stoull(line_v.at(2));
      op.parent_b_ = std::stoull(line_v.at(3));
      op.selection_bit_ = std::stoull(line_v.at(4));
      op.output_wire_ = std::stoull(line_v.at(5));
    } else if (type == std::string("INV")) {
      assert(line_v.size() == 5);
      op.type_ = PrimitiveOperationType::INV;
      op.parent_a_ = std::stoull(line_v.at(2));
      op.output_wire_ = std::stoull(line_v.at(3));
    } else {
      throw std::runtime_error("Unknown operation type: " + line_v.at(line_v.size() - 1) + "\n");
    }
    algo.gates_.emplace_back(op);
    str.clear();
    line_v.clear();
  }
  return algo;
}  // namespace ENCRYPTO
}
