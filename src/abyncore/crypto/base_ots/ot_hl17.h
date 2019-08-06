// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Copyright (c) 2018 Lennart Braun
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

#include <functional>
#include <memory>

#include "flatbuffers/flatbuffers.h"

#include "crypto/curve25519/mycurve25519.h"
#include "ot.h"

namespace ABYN {

class DataStorage;
using DataStoragePtr = std::shared_ptr<DataStorage>;

/**
 * A random OT implementation based on the protocol by Hauck and Loss (2017).
 * https://eprint.iacr.org/2017/1011
 */
class OT_HL17 final : public RandomOT {
 public:
  OT_HL17(std::function<void(flatbuffers::FlatBufferBuilder&&)> send, DataStoragePtr& data_storage);

  /**
   * Send/receive for a single random OT.
   */
  // std::pair<std::vector<std::byte>, std::vector<std::byte>> send() override;
  // std::vector<std::byte> recv(bool) override;

  /**
   * Send/receive parts of the random OT protocol (batch version).
   */
  std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> send(size_t) override;
  std::vector<std::vector<std::byte>> recv(const ENCRYPTO::BitVector<>&) override;
  /**
   * Parallelized version of batch send/receive.
   * These methods will create a new thread pool.
   */
  // std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> parallel_send(
  //    size_t, size_t number_threads) override;
  // std::vector<std::vector<std::byte>> parallel_recv(const std::vector<bool>&,
  //                                                  size_t number_threads) override;

 private:
  std::function<void(flatbuffers::FlatBufferBuilder&&)> Send_;

  DataStoragePtr data_storage_;

  // public:  // for testing
  struct Sender_State {
    Sender_State(std::size_t ot_id) : i(ot_id) {}
    // i-th OT
    const std::size_t i;
    // y
    uint8_t y[32];
    // // S
    curve25519::ge_p3 S;
    // // T
    curve25519::ge_p3 T;
    // // R
    curve25519::ge_p3 R;
  };
  struct Receiver_State {
    Receiver_State(std::size_t ot_id) : i(ot_id) {}

    // i-th OT
    const std::size_t i;

    bool choice;
    // x
    uint8_t x[32];
    // S
    curve25519::ge_p3 S;
    // T
    curve25519::ge_p3 T;
    // R
    curve25519::ge_p3 R;
    // k_R
    // e_c
  };
  static constexpr size_t curve25519_ge_byte_size = 32;

  /**
   * Parts of the sender side.
   */
  void send_0(Sender_State& state, std::array<uint8_t, curve25519_ge_byte_size>& message_out);
  void send_1(Sender_State& state);
  std::pair<std::vector<std::byte>, std::vector<std::byte>> send_2(
      Sender_State& state, const std::array<uint8_t, curve25519_ge_byte_size>& message_in);

  /**
   * Parts of the receiver side.
   */
  void recv_0(Receiver_State& state, bool choice);
  void recv_1(Receiver_State& state, std::array<uint8_t, curve25519_ge_byte_size>& message_out,
              const std::array<uint8_t, curve25519_ge_byte_size>& message_in);
  std::vector<std::byte> recv_2(Receiver_State& state);
};
}