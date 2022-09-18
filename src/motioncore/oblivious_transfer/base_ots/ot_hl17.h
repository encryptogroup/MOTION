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

#include "ot.h"

#include <flatbuffers/flatbuffers.h>

#include <functional>
#include <memory>
#include <span>

#include "primitives/curve25519/mycurve25519.h"

namespace encrypto::motion {

struct BaseOtData;

/**
 * A random OT implementation based on the protocol by Hauck and Loss (2017).
 * https://eprint.iacr.org/2017/1011
 */
class OtHL17 final : public RandomOt {
 public:
  OtHL17(std::function<void(flatbuffers::FlatBufferBuilder&&)> send, BaseOtData& data_storage);

  /**
   * Send/receive for a single random OT.
   */
  // std::pair<std::vector<std::byte>, std::vector<std::byte>> send() override;
  // std::vector<std::byte> recv(bool) override;

  /**
   * Send/receive parts of the random OT protocol (batch version).
   */
  std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> Send(size_t) override;
  std::vector<std::vector<std::byte>> Receive(const BitVector<>&) override;
  /**
   * Parallelized version of batch send/receive.
   * These methods will create a new thread pool.
   */
  // std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> parallel_send(
  //    size_t, size_t number_threads) override;
  // std::vector<std::vector<std::byte>> parallel_recv(const std::vector<bool>&,
  //                                                  size_t number_threads) override;

 private:
  std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function_;

  BaseOtData& base_ots_data_;

  // public:  // for testing
  struct SenderState {
    SenderState(std::size_t ot_id) : i(ot_id) {}
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

  struct ReceiverState {
    ReceiverState(std::size_t ot_id) : i(ot_id) {}

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

  static constexpr size_t kCurve25519GeByteSize = 32;

  /**
   * Parts of the sender side.
   */
  void Send0(SenderState& state, std::span<std::uint8_t> message_output);
  void Send1(SenderState& state);
  std::pair<std::vector<std::byte>, std::vector<std::byte>> Send2(
      SenderState& state, std::span<const std::uint8_t> message_input);

  /**
   * Parts of the receiver side.
   */
  void Receive0(ReceiverState& state, bool choice);
  void Receive1(ReceiverState& state, std::span<std::uint8_t> message_output,
                std::span<const std::uint8_t> message_input);
  std::vector<std::byte> Receive2(ReceiverState& state);
};

}  // namespace encrypto::motion
