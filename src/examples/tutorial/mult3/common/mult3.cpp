// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include "mult3.h"

#include <fstream>
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/bit_vector.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer& party,
                                                     encrypto::motion::MpcProtocol protocol,
                                                     const std::uint32_t input_command_line,
                                                     const std::string& input_file_path,
                                                     const std::string& input_file_shared_path,
                                                     bool print_output) {
  encrypto::motion::SecureUnsignedInteger output;
  /* Checks if shared input file's path is empty, if that's the case, continues and uses either
   * input from file given in input_file_path or from command line.
   * */
  if (input_file_shared_path.empty()) {
    output = ComputeInput(party, protocol, input_command_line, input_file_path);
  } else {
    output = ComputeSharedInput(party, protocol, input_file_shared_path);
  }

  // Constructs an output gate for the output.
  output = output.Out();

  party->Run();

  // Converts the output to an integer.
  auto result = output.As<std::uint32_t>();

  if (print_output) std::cout << "Result = " << result << std::endl;

  party->Finish();

  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/**
 * Computes Mult3 using input from file or command line.
 * File's path is given in input_file_path.
 */
encrypto::motion::SecureUnsignedInteger ComputeInput(encrypto::motion::PartyPointer& party,
                                                     encrypto::motion::MpcProtocol protocol,
                                                     const std::uint32_t input_command_line,
                                                     const std::string& input_file_path) {
  std::array<encrypto::motion::SecureUnsignedInteger, 3> shared_input;
  std::uint32_t input;

  // Checks if there is no input from command line.
  if (input_file_path.empty()) {
    input = input_command_line;  // Takes input as an integer from terminal.
  } else {
    // Takes input from file, path is given in input_file_path.
    input = GetFileInput(input_file_path);
  }

  /* Assigns input to its party using the given protocol.
   * The same input will be used as a dummy input for the other party, but only the party with the
   * same id will really set the input.
   * */
  switch (protocol) {
    case encrypto::motion::MpcProtocol::kArithmeticGmw: {
      for (std::size_t i = 0; i < 3; i++) {
        shared_input[i] = party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(input, i);
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      for (std::size_t i = 0; i < 3; i++) {
        shared_input[i] = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(
            encrypto::motion::ToInput(input), i);
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      for (std::size_t i = 0; i < 3; i++) {
        shared_input[i] =
            party->In<encrypto::motion::MpcProtocol::kBmr>(encrypto::motion::ToInput(input), i);
      }
      break;
    }
    default:
      throw std::invalid_argument("Invalid MPC protocol");
  }

  return CreateMult3Circuit(shared_input[0], shared_input[1], shared_input[2]);
}

/**
 * Computes Mult3 using shared input from file.
 * Path is given in input_file_shared_path.
 */
encrypto::motion::SecureUnsignedInteger ComputeSharedInput(
    encrypto::motion::PartyPointer& party, encrypto::motion::MpcProtocol protocol,
    const std::string& input_file_shared_path) {
  std::array<encrypto::motion::SecureUnsignedInteger, 3> shared_input;

  // Takes shared input from file, path is given in input_file_shared_path.
  const std::vector<std::uint32_t> preshared_input = GetFileSharedInput(input_file_shared_path);

  // Assigns shared input to its party (only supports ArithmeticGMW and BooleanGMW).
  switch (protocol) {
    case encrypto::motion::MpcProtocol::kArithmeticGmw: {
      for (std::size_t i = 0; i < 3; i++) {
        shared_input[i] =
            party->SharedIn<encrypto::motion::MpcProtocol::kArithmeticGmw>(preshared_input[i]);
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      for (std::size_t i = 0; i < 3; i++) {
        shared_input[i] = party->SharedIn<encrypto::motion::MpcProtocol::kBooleanGmw>(
            encrypto::motion::ToInput(preshared_input[i]));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      throw std::invalid_argument("Mult3Shared doesn't support Bmr protocol");
      break;
    }
    default:
      throw std::invalid_argument("Invalid MPC protocol");
  }

  return CreateMult3Circuit(shared_input[0], shared_input[1], shared_input[2]);
}

/**
 * Constructs the multiplication of the three given inputs.
 */
encrypto::motion::SecureUnsignedInteger CreateMult3Circuit(
    encrypto::motion::SecureUnsignedInteger a, encrypto::motion::SecureUnsignedInteger b,
    encrypto::motion::SecureUnsignedInteger c) {
  return a * b * c;
}

/**
 * Takes input as an integer from file in path.
 */
std::uint32_t GetFileInput(const std::string& path) {
  std::ifstream infile;
  std::uint32_t input;

  infile.open(path);
  if (!infile.is_open()) throw std::runtime_error("Could not open Mult3 file");

  infile >> input;
  infile.close();
  return input;
}

/**
 * Takes input as a vector of integers from file in path.
 */
std::vector<std::uint32_t> GetFileSharedInput(const std::string& path) {
  std::ifstream infile;
  std::vector<std::uint32_t> input;
  std::uint32_t x;

  infile.open(path);
  if (!infile.is_open()) throw std::runtime_error("Could not open Mult3Shared file");

  while (infile >> x) input.push_back(x);
  infile.close();
  return input;
}
