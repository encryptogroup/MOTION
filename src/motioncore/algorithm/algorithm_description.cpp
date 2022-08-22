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

#include <fmt/format.h>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

namespace encrypto::motion {

AlgorithmDescription AlgorithmDescription::FromBristol(const std::string& path) {
  std::ifstream file_stream(path);
  return FromBristol(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristol(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromBristol(file_stream);
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
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());
  stream >> algorithm_description.number_of_gates >> algorithm_description.number_of_wires;

  std::vector<std::string> line_vector;
  std::string line;
  std::getline(stream, line);  // skip \n at the end of the first line
  // second line
  {
    std::string second_line;
    std::getline(stream, second_line);
    std::stringstream ss(second_line);
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
      line.clear();
    }
    algorithm_description.number_of_input_wires_parent_a = std::stoull(line_vector.at(0));
    if (line_vector.size() == 2) {
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(1));
    } else if (line_vector.size() == 3) {
      algorithm_description.number_of_input_wires_parent_b = std::stoull(line_vector.at(1));
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(2));
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " + std::to_string(line_vector.size()) + "\n"));
    }
    line.clear();
    line_vector.clear();
  }

  std::getline(stream, line);
  assert(line.empty());

  // read line
  while (std::getline(stream, line)) {
    std::stringstream ss(line);
    // split line
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
    }

    if (line_vector.empty()) continue;
    const auto& type = line_vector.at(line_vector.size() - 1);
    PrimitiveOperation primitive_operation;
    if (type == std::string("XOR") || type == std::string("AND") || type == std::string("ADD") ||
        type == std::string("MUL") || type == std::string("OR")) {
      assert(line_vector.size() == 6);
      if (type == std::string("XOR"))
        primitive_operation.type = PrimitiveOperationType::kXor;
      else if (type == std::string("AND"))
        primitive_operation.type = PrimitiveOperationType::kAnd;
      else if (type == std::string("ADD"))
        primitive_operation.type = PrimitiveOperationType::kAdd;
      else if (type == std::string("MUL"))
        primitive_operation.type = PrimitiveOperationType::kMul;
      else if (type == std::string("OR"))
        primitive_operation.type = PrimitiveOperationType::kOr;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.output_wire = std::stoull(line_vector.at(4));
    } else if (type == std::string("MUX")) {
      assert(line_vector.size() == 7);
      primitive_operation.type = PrimitiveOperationType::kMux;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.selection_bit = std::stoull(line_vector.at(4));
      primitive_operation.output_wire = std::stoull(line_vector.at(5));
    } else if (type == std::string("INV")) {
      assert(line_vector.size() == 5);
      primitive_operation.type = PrimitiveOperationType::kInv;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.output_wire = std::stoull(line_vector.at(3));
    } else {
      throw std::runtime_error("Unknown operation type: " + line_vector.at(line_vector.size() - 1) +
                               "\n");
    }
    algorithm_description.gates.emplace_back(primitive_operation);
    line.clear();
    line_vector.clear();
  }
  return algorithm_description;
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(const std::string& path) {
  std::ifstream file_stream(path);
  return FromBristolFashion(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromBristolFashion(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());

  constexpr std::size_t kGateEncodingLineNumber = 4;
  const static std::regex kLineTwoNumbersRegex("^\\s*(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex kLineThreeNumbersRegex("^\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex kLineGateRegex(
      "^\\s*(1|2)\\s+(1)\\s+(\\d+)\\s+(\\d+\\s+)?(\\d+)\\s+(XOR|AND|INV)\\s*$");
  const static std::regex kLineWhitespaceRegex("^\\s*$");

  std::string line;
  std::smatch match;

  // first line
  std::getline(stream, line);
  if (!std::regex_match(line, match, kLineTwoNumbersRegex)) {
    throw std::runtime_error("Cannot parse Bristol Fashion file at line 1");
  }
  algorithm_description.number_of_gates = boost::lexical_cast<std::size_t>(match[1]);
  algorithm_description.number_of_wires = boost::lexical_cast<std::size_t>(match[2]);

  // second line
  std::getline(stream, line);
  if (std::regex_match(line, match, kLineTwoNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algorithm_description.number_of_input_wires_parent_a =
        boost::lexical_cast<std::size_t>(match[2]);
  } else if (std::regex_match(line, match, kLineThreeNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 2) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algorithm_description.number_of_input_wires_parent_a =
        boost::lexical_cast<std::size_t>(match[2]);
    algorithm_description.number_of_input_wires_parent_b =
        boost::lexical_cast<std::size_t>(match[3]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 2 (maybe unsupported number of input values)");
  }

  // third line
  std::getline(stream, line);
  if (std::regex_match(line, match, kLineTwoNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 3");
    }
    algorithm_description.number_of_output_wires = boost::lexical_cast<std::size_t>(match[2]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 3 (maybe unsupported number of output values)");
  }

  // consume empty line
  std::getline(stream, line);
  assert(line.empty());

  std::size_t line_number = kGateEncodingLineNumber;

  // read gates
  while (std::getline(stream, line)) {
    ++line_number;
    if (line.empty() || std::regex_match(line, kLineWhitespaceRegex)) {
      continue;
    }

    if (!std::regex_match(line, match, kLineGateRegex)) {
      throw std::runtime_error(
          fmt::format("Cannot parse Bristol Fashion file at line {}", line_number));
    }

    using namespace std::string_literals;

    auto number_of_inputs = boost::lexical_cast<std::size_t>(match[1]);
    const auto& operation = match[6];
    PrimitiveOperation primitive_operation;

    if (operation == "XOR"s) {
      if (number_of_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kXor;
    } else if (operation == "AND"s) {
      if (number_of_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kAnd;
    } else if (operation == "INV"s) {
      if (number_of_inputs != 1) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kInv;
    }
    primitive_operation.output_wire = boost::lexical_cast<std::size_t>(match[5]);
    primitive_operation.parent_a = boost::lexical_cast<std::size_t>(match[3]);
    if (number_of_inputs == 2) {
      std::string input_b = match[4];
      boost::trim(input_b);
      primitive_operation.parent_b = boost::lexical_cast<std::size_t>(input_b);
    }
    algorithm_description.gates.emplace_back(std::move(primitive_operation));
  }

  return algorithm_description;
}

AlgorithmDescription AlgorithmDescription::FromAby(const std::string& path) {
  std::ifstream file_stream(path);
  return FromBristol(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromAby(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromBristol(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromAby(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());
  std::string line;
  constexpr int kInvalidValue = 999999999;
  int constant_input_0 [[maybe_unused]] = kInvalidValue;
  int constant_input_1 [[maybe_unused]] = kInvalidValue;
  do {
    std::getline(stream, line);
    switch (line[0]) {
      case '#':  // comment
        break;
      case '\n':  // empty line
        break;
      case '0':  // constant 0
        constant_input_0 = std::stoi(line.substr(1, line.size() - 1));
        break;
      case '1':  // constant 1
        constant_input_1 = std::stoi(line.substr(1, line.size() - 1));
        break;
      case 'C': {  // client's inputs
        std::stringstream ss(line);
        std::string value;
        std::getline(ss, value, ' ');
        assert(value == "C");
        while (std::getline(ss, value, ' ')) ++algorithm_description.number_of_input_wires_parent_a;
        break;
      }
      case 'S': {  // server's inputs
        std::stringstream ss(line);
        std::string value;
        std::getline(ss, value, ' ');
        assert(value == "S");
        while (std::getline(ss, value, ' ')) ++algorithm_description.number_of_input_wires_parent_a;
        break;
      }
      default:
        throw std::logic_error(std::string("Invalid first symbol ") + line[0]);
    }
  } while (line != "#Gates");
  std::vector<std::string> line_vector;

  assert(constant_input_0 != kInvalidValue);
  assert(constant_input_1 != kInvalidValue);

  // read gates
  do {
    std::getline(stream, line);
    if (line.size() <= 1) continue;
    switch (line[0]) {
      case 'A':  // AND gate, `A 101 102 103` denotes 103 = 101 AND 102
        // AND with constant_input_1 is the same gate
        // AND with constant_input_0 is illegal for now
        break;
      case 'I':  // INV gate, `I 101 102` denotes that 102 = NOT 101
        break;
      case 'M':  // MUX gate, `M 101 102 103 104` denotes 104 = 103 ? 102 : 101
        break;
      case 'X':  // XOR gate, `X 101 102 103` denotes 103 = 101 XOR 102
        // XOR with constant_input_1 is an INV gate
        // XOR with constant_input_0 is the same gate
        break;
      default:
        throw std::logic_error(std::string("Invalid first symbol ") + line[0]);
    }
    std::stringstream ss(line);
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
      line.clear();
    }
    algorithm_description.number_of_input_wires_parent_a = std::stoull(line_vector.at(0));
    if (line_vector.size() == 2) {
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(1));
    } else if (line_vector.size() == 3) {
      algorithm_description.number_of_input_wires_parent_b = std::stoull(line_vector.at(1));
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(2));
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " + std::to_string(line_vector.size()) + "\n"));
    }
    line.clear();
    line_vector.clear();
  } while (line != "\n");

  assert(line.empty());

  // read output IDs
  while (std::getline(stream, line)) {
    std::stringstream ss(line);
    // split line
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
    }

    if (line_vector.empty()) continue;
    const auto& type = line_vector.at(line_vector.size() - 1);
    PrimitiveOperation primitive_operation;
    if (type == std::string("XOR") || type == std::string("AND") || type == std::string("ADD") ||
        type == std::string("MUL") || type == std::string("OR")) {
      assert(line_vector.size() == 6);
      if (type == std::string("XOR"))
        primitive_operation.type = PrimitiveOperationType::kXor;
      else if (type == std::string("AND"))
        primitive_operation.type = PrimitiveOperationType::kAnd;
      else if (type == std::string("ADD"))
        primitive_operation.type = PrimitiveOperationType::kAdd;
      else if (type == std::string("MUL"))
        primitive_operation.type = PrimitiveOperationType::kMul;
      else if (type == std::string("OR"))
        primitive_operation.type = PrimitiveOperationType::kOr;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.output_wire = std::stoull(line_vector.at(4));
    } else if (type == std::string("MUX")) {
      assert(line_vector.size() == 7);
      primitive_operation.type = PrimitiveOperationType::kMux;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.selection_bit = std::stoull(line_vector.at(4));
      primitive_operation.output_wire = std::stoull(line_vector.at(5));
    } else if (type == std::string("INV")) {
      assert(line_vector.size() == 5);
      primitive_operation.type = PrimitiveOperationType::kInv;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.output_wire = std::stoull(line_vector.at(3));
    } else {
      throw std::runtime_error("Unknown operation type: " + line_vector.at(line_vector.size() - 1) +
                               "\n");
    }
    algorithm_description.gates.emplace_back(primitive_operation);
    line.clear();
    line_vector.clear();
  }
  return algorithm_description;
}

}  // namespace encrypto::motion
