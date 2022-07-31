// MIT License
//
// Copyright (c) 2019-2022 Oleksandr Tkachenko, Lennart Braun, Arianne Roselina Prananto
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
#include "utility/fiber_waitable.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion {

class Configuration;
class Logger;
class Register;

using BaseOtMessages = std::vector<std::array<std::byte, 16>>;

struct SenderMessage {
  BaseOtMessages messages_0;
  BaseOtMessages messages_1;
};

struct ReceiverMessage {
  BaseOtMessages messages_c;
  BitVector<> c;
};

class BaseOtProvider : public FiberOnlineWaitable {
 public:
  BaseOtProvider(communication::CommunicationLayer&);
  ~BaseOtProvider();
  void ComputeBaseOts();
  void ImportBaseOts(std::size_t party_id, const ReceiverMessage& messages);
  void ImportBaseOts(std::size_t party_id, const SenderMessage& messages);
  std::pair<ReceiverMessage, SenderMessage> ExportBaseOts(std::size_t party_id);
  BaseOtData& GetBaseOtsData(std::size_t party_id) { return data_.at(party_id); }
  const BaseOtData& GetBaseOtsData(std::size_t party_id) const { return data_.at(party_id); }
  void PreSetup();
  bool HasWork();

  /// \brief Add the number of Base OTs for each party. Must be called before PreSetup()
  std::vector<std::size_t> Request(std::size_t number_of_ots);

  /// \brief Add the number of Base OTs for party with this id. Must be called before PreSetup()
  std::size_t Request(std::size_t number_of_ots, std::size_t party_id);

 private:
  std::vector<std::size_t> number_of_ots_;
  communication::CommunicationLayer& communication_layer_;
  std::size_t number_of_parties_;
  std::size_t my_id_;
  std::vector<BaseOtData> data_;
  std::shared_ptr<Logger> logger_;

  Logger& GetLogger();
};

}  // namespace encrypto::motion
