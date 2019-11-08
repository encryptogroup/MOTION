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

#include "algorithm_description.h"

#include <fstream>
#include <sstream>

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

    if(line_v.empty()) continue;
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

}