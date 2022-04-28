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

#pragma once

#include <flatbuffers/flatbuffers.h>
#include <span>

#include "fbs_headers/message_generated.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type);

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type, std::size_t message_id,
                                            std::span<const uint8_t> payload);

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                            std::span<const uint8_t> payload);

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                            const std::vector<uint8_t>* payload);

// Give a human readable representation of MessageType values
std::string to_string(MessageType message_type);

}  // namespace encrypto::motion::communication
