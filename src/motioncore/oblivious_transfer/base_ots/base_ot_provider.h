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

#pragma once

#include <array>
#include <cstddef>

#include "data_storage/base_ot_data.h"
#include "utility/bit_vector.h"
#include "utility/constants.h"

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion {

class Configuration;
class Logger;
class Register;

using BaseOtMessages = std::array<std::array<std::byte, 16>, kKappa>;

struct SenderMessage {
  BaseOtMessages messages_0;
  BaseOtMessages messages_1;
};

struct ReceiverMessage {
  BaseOtMessages messages_c;
  BitVector<> c;
};

class BaseOtProvider {
 public:
  BaseOtProvider(communication::CommunicationLayer&, std::shared_ptr<Logger>);
  ~BaseOtProvider();
  void ComputeBaseOts();
  void ImportBaseOts(std::size_t party_id, const ReceiverMessage& messages);
  void ImportBaseOts(std::size_t party_id, const SenderMessage& messages);
  std::pair<ReceiverMessage, SenderMessage> ExportBaseOts(std::size_t party_id);
  BaseOtData& GetBaseOtsData(std::size_t party_id) { return data_.at(party_id); }
  const BaseOtData& GetBaseOtsData(std::size_t party_id) const { return data_.at(party_id); }

 private:
  communication::CommunicationLayer& communication_layer_;
  std::size_t number_of_parties_;
  std::size_t my_id_;
  std::vector<BaseOtData> data_;
  std::shared_ptr<Logger> logger_;
  bool finished_;

  Logger& GetLogger();
};

}  // namespace encrypto::motion
