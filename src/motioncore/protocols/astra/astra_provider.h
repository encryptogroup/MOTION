// MIT License
//
// Copyright (c) 2022 Oliver Schick
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

#include <cstdint>
#include <map>
#include <mutex>

#include "communication/fbs_headers/message_generated.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion::proto::astra {

class Condition;

enum DataType : unsigned int { 
    kInput, 
    kMultiplySetup, 
    kMultiplyOnline,
    kDotProductSetup,
    kDotProductOnline
};

class Provider {
 public:
  Provider(communication::CommunicationLayer& communication_layer);
  ~Provider() = default;
  
  using Promise = ReusableFiberPromise<std::vector<uint8_t>>;
  using Future = ReusableFiberFuture<std::vector<uint8_t>>;
      
  void PostData(communication::MessageType const& type, std::size_t gate_id, std::vector<uint8_t>&& data);
  
  Future RegisterReceivingGate(std::size_t gate_id);
  
  Future RegisterOnlineReceivingMultiplicationGate(std::size_t gate_id);
  
  std::size_t UnregisterReceivingGate(std::size_t gate_id);

 private:
  
  communication::CommunicationLayer& communication_layer_;
  std::map<std::size_t, Promise> messages_;
  std::map<std::size_t, Promise> online_multiplication_messages_;
  std::mutex m_;
};

}  // namespace encrypto::motion::proto::bmr