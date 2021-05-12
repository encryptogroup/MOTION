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

#pragma once

#include "base/party.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/run_time_statistics.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer& party,
                                                     encrypto::motion::MpcProtocol protocol,
                                                     const std::uint32_t input_command_line,
                                                     const std::string& input_file_path,
                                                     const std::string& input_file_shared_path,
                                                     bool print_output);

encrypto::motion::SecureUnsignedInteger ComputeInput(encrypto::motion::PartyPointer& party,
                                                     encrypto::motion::MpcProtocol protocol,
                                                     const std::uint32_t input_command_line,
                                                     const std::string& input_file_path);

encrypto::motion::SecureUnsignedInteger ComputeSharedInput(
    encrypto::motion::PartyPointer& party, encrypto::motion::MpcProtocol protocol,
    const std::string& input_file_shared_path);

encrypto::motion::SecureUnsignedInteger CreateMult3Circuit(
    encrypto::motion::SecureUnsignedInteger a, encrypto::motion::SecureUnsignedInteger b,
    encrypto::motion::SecureUnsignedInteger c);

std::uint32_t GetFileInput(const std::string& path);

std::vector<std::uint32_t> GetFileSharedInput(const std::string& path);
