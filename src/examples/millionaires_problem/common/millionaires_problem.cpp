// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Daniel Demmler, Tobias Kussel
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

#include "millionaires_problem.h"

#include <cstddef>
#include <vector>
#include <limits>

#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/config.h"

// abbreviate namespace
namespace mo = encrypto::motion;

void EvaluateProtocol(mo::PartyPointer& party, std::uint32_t value) {
  const std::size_t number_of_parties{party->GetConfiguration()->GetNumOfParties()};

  // (pre-)allocate indices and input values
  std::vector<mo::SecureUnsignedInteger> indices(number_of_parties), input_values(number_of_parties);
  
  // share inputs
  // remark: the input values to other parties' input gates are considered as buffers 
  // and the values are simply ignored and overwritten later
  for (std::uint32_t i = 0; i < number_of_parties; ++i) {
    input_values[i] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(value), i);
    indices[i] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(i), 0);
  }

  // set the default max id and value to be that of Party 0
  mo::SecureUnsignedInteger max_id{indices[0]}, max_val{input_values[0]};
  
  // find the max id and value among all parties' inputs
  for (std::uint32_t i = 1; i < number_of_parties; ++i) {
    auto comparison = max_val > input_values[i];
    max_val = comparison.Mux(max_val.Get(), input_values[i].Get());
    max_id = comparison.Mux(max_id.Get(), indices[i].Get());
  }
  
  // construct an output gate
  auto output = max_id.Out();
  
  // run the protocol
  party->Run();
  party->Finish();

  // retrieve the result
  auto result = output.As<std::uint32_t>();
  // print the result into the terminal
  std::cout << "Party " << result << " is the richest party." << std::endl;
}
