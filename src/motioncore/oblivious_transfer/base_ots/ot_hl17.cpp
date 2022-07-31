// MIT License
//
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

#include "ot_hl17.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>

#include "base/backend.h"
#include "communication/message.h"
#include "data_storage/base_ot_data.h"
#include "primitives/blake2b.h"
#include "utility/helpers.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

OtHL17::OtHL17(std::function<void(flatbuffers::FlatBufferBuilder&&)> send,
               BaseOtData& base_ots_data)
    : send_function_(send), base_ots_data_(base_ots_data) {}

// Notation
// * Group GG
// * of prime order p
// * with generator g
//
// * random oracle G: GG -> GG
// * random oracle H: GG^3 -> K

void HashPoint(curve25519::ge_p3& output, const curve25519::ge_p3& input) {
  std::array<uint8_t, 32> hash_input;
  std::vector<uint8_t> hash_output(EVP_MAX_MD_SIZE);

  curve25519::ge_p3_tobytes(hash_input.data(), &input);
  Blake2b(hash_input.data(), hash_output.data(), hash_input.size());
  hash_output.resize(32);

  curve25519::x25519_sc_reduce(hash_output.data());
  curve25519::x25519_ge_scalarmult_base(&output, hash_output.data());
}

void OtHL17::Send0(SenderState& state, std::span<std::uint8_t> message_output) {
  // sample y <- Zp
  curve25519::sc_random(state.y);

  // S = g^y
  curve25519::x25519_ge_scalarmult_base(&state.S, state.y);

  std::vector<std::byte> S_bytes(kCurve25519GeByteSize);
  curve25519::ge_p3_tobytes(reinterpret_cast<std::uint8_t*>(message_output.data()), &state.S);
}

void OtHL17::Send1(SenderState& state) {
  // T = G(S)
  HashPoint(state.T, state.S);
}

std::pair<std::vector<std::byte>, std::vector<std::byte>> OtHL17::Send2(
    SenderState& state, std::span<const std::uint8_t> message_input) {
  assert(message_input.size() == kCurve25519GeByteSize);
  // assert R in GG
  if (!x25519_ge_frombytes_vartime(&state.R, message_input.data())) {
    throw std::runtime_error("Base OT: R is not in G - abort");
  }

  auto md_context = NewBlakeCtx();

  auto output = std::make_pair<>(std::vector<std::byte>(EVP_MAX_MD_SIZE),
                                 std::vector<std::byte>(EVP_MAX_MD_SIZE));
  assert(output.first.size() == EVP_MAX_MD_SIZE);
  assert(output.second.size() == EVP_MAX_MD_SIZE);

  std::array<uint8_t, 3 * kCurve25519GeByteSize> hash_input;
  curve25519::ge_p3_tobytes(hash_input.data(), &state.S);
  curve25519::ge_p3_tobytes(hash_input.data() + 32, &state.R);

  // j = 0:
  // y*R
  curve25519::ge_p2 y_times_R_p2;
  curve25519::x25519_ge_scalarmult(&y_times_R_p2, state.y, &state.R);
  curve25519::x25519_ge_tobytes(hash_input.data() + 64, &y_times_R_p2);

  // H(S, R, y*R)
  Blake2b(hash_input.data(), reinterpret_cast<uint8_t*>(output.first.data()), hash_input.size(),
          md_context);

  // j = 1:
  // y*R + (-y)*T = y*(R - T)
  {
    curve25519::ge_cached T_cached;
    curve25519::x25519_ge_p3_to_cached(&T_cached, &state.T);

    curve25519::ge_p1p1 R_minus_T_p1p1;
    curve25519::x25519_ge_sub(&R_minus_T_p1p1, &state.R, &T_cached);

    curve25519::ge_p3 R_minus_T_p3;
    curve25519::x25519_ge_p1p1_to_p3(&R_minus_T_p3, &R_minus_T_p1p1);

    curve25519::ge_p2 y_times_R_minus_T_p2;
    curve25519::x25519_ge_scalarmult(&y_times_R_minus_T_p2, state.y, &R_minus_T_p3);
    curve25519::x25519_ge_tobytes(hash_input.data() + 64, &y_times_R_minus_T_p2);
  }

  // H(S, R, y*R - y*T)
  Blake2b(hash_input.data(), reinterpret_cast<uint8_t*>(output.second.data()), hash_input.size(),
          md_context);

  output.first.resize(16);
  output.second.resize(16);

  return output;
}

void OtHL17::Receive0(ReceiverState& state, bool choice) {
  state.choice = choice;
  // sample x <- Zp
  curve25519::sc_random(state.x);
}

void OtHL17::Receive1(ReceiverState& state, std::span<std::uint8_t> message_output,
                      std::span<const std::uint8_t> message_input) {
  assert(message_input.size() == kCurve25519GeByteSize);
  // recv S
  auto res = curve25519::x25519_ge_frombytes_vartime(
      &state.S, reinterpret_cast<const std::uint8_t*>(message_input.data()));
  // assert S in GG
  if (res == 0) {
    throw std::runtime_error("Base OT: S is not in G - abort");
  }

  // T = G(S)
  HashPoint(state.T, state.S);

  // R = T^c * g^x

  // R = g^x
  curve25519::x25519_ge_scalarmult_base(&state.R, state.x);

  // FIXME: not constant time
  // R = R * T
  if (state.choice) {
    curve25519::ge_p1p1 R_p1p1;
    curve25519::ge_cached T_cached;
    curve25519::x25519_ge_p3_to_cached(&T_cached, &state.T);
    curve25519::x25519_ge_add(&R_p1p1, &state.R, &T_cached);
    curve25519::x25519_ge_p1p1_to_p3(&state.R, &R_p1p1);
  }

  std::vector<std::byte> R_bytes(32);
  curve25519::ge_p3_tobytes(reinterpret_cast<std::uint8_t*>(message_output.data()), &state.R);
}

std::vector<std::byte> OtHL17::Receive2(ReceiverState& state) {
  // k_R = H_(S,R)(S^x)
  //     = H_(S,R)(g^xy)

  std::vector<std::byte> hash_output(EVP_MAX_MD_SIZE);

  std::array<uint8_t, 3 * kCurve25519GeByteSize> hash_input;
  curve25519::ge_p3_tobytes(hash_input.data(), &state.S);
  curve25519::ge_p3_tobytes(hash_input.data() + kCurve25519GeByteSize, &state.R);

  curve25519::ge_p2 S_to_the_x;
  curve25519::x25519_ge_scalarmult(&S_to_the_x, state.x, &state.S);
  curve25519::x25519_ge_tobytes(hash_input.data() + 2 * kCurve25519GeByteSize, &S_to_the_x);

  assert(hash_output.size() == EVP_MAX_MD_SIZE);
  Blake2b(hash_input.data(), reinterpret_cast<uint8_t*>(hash_output.data()), hash_input.size());

  hash_output.resize(16);
  return hash_output;
}

std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> OtHL17::Send(
    size_t number_of_ots) {
  std::vector<SenderState> states;
  for (std::size_t i = 0; i < number_of_ots; ++i) {
    states.emplace_back(i);
  }

  auto& base_ots_sender = base_ots_data_.sender_data;

  std::vector<std::array<std::uint8_t, kCurve25519GeByteSize>> messages_s0(number_of_ots);
  std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> output(number_of_ots);

  for (std::size_t i = 0; i < number_of_ots; ++i) {
    Send0(states[i], messages_s0[i]);
  }

  for (std::size_t i = 0; i < number_of_ots; ++i) {
    std::span s(reinterpret_cast<const std::uint8_t*>(messages_s0[i].data()),
                messages_s0[i].size());
    auto msg{communication::BuildMessage(communication::MessageType::kBaseROtMessageSender, i, s)};
    send_function_(std::move(msg));
    Send1(states[i]);
  }

  for (std::size_t i = 0; i < number_of_ots; ++i) {
    auto raw_message{base_ots_data_.receiver_futures[i].get()};
    auto payload{communication::GetMessage(raw_message.data())->payload()};
    output.at(i) = Send2(states.at(i), std::span(payload->data(), payload->size()));
  }

  base_ots_sender.SetOnlineIsReady();

  return output;
}

std::vector<std::vector<std::byte>> OtHL17::Receive(const BitVector<>& choices) {
  const auto number_of_ots = choices.GetSize();
  auto& base_ots_receiver = base_ots_data_.receiver_data;
  std::vector<ReceiverState> states;
  for (std::size_t i = 0; i < number_of_ots; ++i) {
    states.emplace_back(i);
  }
  std::vector<std::array<std::uint8_t, kCurve25519GeByteSize>> messages_r1(number_of_ots);
  std::vector<std::vector<std::byte>> output(number_of_ots);

  for (std::size_t i = 0; i < number_of_ots; ++i) {
    Receive0(states.at(i), choices.Get(i));
  }

  for (std::size_t i = 0; i < number_of_ots; ++i) {
    auto raw_message{base_ots_data_.sender_futures[i].get()};
    auto payload{communication::GetMessage(raw_message.data())->payload()};
    Receive1(states[i], messages_r1[i], std::span(payload->data(), payload->size()));
    std::span s(reinterpret_cast<const std::uint8_t*>(messages_r1[i].data()),
                messages_r1[i].size());
    auto msg{
        communication::BuildMessage(communication::MessageType::kBaseROtMessageReceiver, i, s)};
    send_function_(std::move(msg));
  }

  for (std::size_t i = 0; i < number_of_ots; ++i) {
    output.at(i) = Receive2(states.at(i));
  }

  base_ots_receiver.SetOnlineIsReady();

  return output;
}

}  // namespace encrypto::motion
