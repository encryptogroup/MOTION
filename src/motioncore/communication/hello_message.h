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
#include "utility/constants.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildHelloMessage(
    const uint16_t source_id = 0, uint16_t destination_id = 0, uint16_t number_of_parties = 0,
    const std::vector<uint8_t>* input_sharing_seed = nullptr,
    const std::vector<uint8_t>* global_sharing_seed = nullptr,
    const std::vector<uint8_t>* fixed_key_aes_seed = nullptr, bool online_after_setup = false,
    std::uint16_t motion_version_major = kMotionVersionMajor,
    std::uint16_t motion_version_minor = kMotionVersionMinor,
    std::uint16_t motion_version_patch = kMotionVersionPatch);

}  // namespace encrypto::motion::communication
