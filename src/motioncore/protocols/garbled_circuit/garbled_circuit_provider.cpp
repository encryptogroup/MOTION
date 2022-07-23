// MIT License
//
// Copyright (c) 2021-2022 Oleksandr Tkachenko
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

#include "garbled_circuit_provider.h"

#include "communication/communication_layer.h"
#include "communication/fbs_headers/garbled_circuit_message_generated.h"
#include "communication/garbled_circuit_message.h"
#include "garbled_circuit_constants.h"
#include "garbled_circuit_utility.h"
#include "garbled_circuit_wire.h"

namespace encrypto::motion::proto::garbled_circuit {

Provider::Provider(communication::CommunicationLayer& communication_layer)
    : communication_layer_(communication_layer) {
  if (communication_layer_.GetNumberOfParties() != 2) {
    throw std::invalid_argument(
        fmt::format("Garbled circuits can only be run with exactly two parties but #parties={}",
                    communication_layer_.GetNumberOfParties()));
  }
}

void ThreeHalvesGarblerProvider::Setup() {
  if constexpr (kDebug) {
    communication_layer_.GetLogger()->LogDebug(
        "Started evaluating setup phase of ThreeHalvesGarblerProvider");
  }

  flatbuffers::FlatBufferBuilder builder{
      encrypto::motion::communication::BuildGarbledCircuitSetupMessage(
          std::span(round_keys_.data(), Block128::kBlockSize),
          std::span(public_data_.hash_key.data(), Block128::kBlockSize))};
  auto evaluator_id{static_cast<std::size_t>(GarbledCircuitRole::kEvaluator)};
  communication_layer_.SendMessage(evaluator_id, builder.Release());

  SetSetupIsReady();

  if constexpr (kDebug) {
    communication_layer_.GetLogger()->LogDebug(
        "Finished evaluating setup phase of ThreeHalvesGarblerProvider");
  }
}

void ThreeHalvesEvaluatorProvider::Setup() {
  if constexpr (kDebug) {
    communication_layer_.GetLogger()->LogDebug(
        "Started evaluating setup phase of ThreeHalvesEvaluatorProvider");
  }

  auto public_data_msg{three_halves_public_data_future_.get()};
  auto payload{communication::GetMessage(public_data_msg.data())->payload()};
  auto setup_msg{flatbuffers::GetRoot<communication::GarbledCircuitSetupMessage>(payload->data())};

  std::copy_n(setup_msg->aes_key()->data(), Block128::kBlockSize,
              reinterpret_cast<std::uint8_t*>(public_data_.aes_key.data()));
  std::copy_n(setup_msg->hash_key()->data(), Block128::kBlockSize,
              reinterpret_cast<std::uint8_t*>(public_data_.hash_key.data()));
  std::copy_n(public_data_.aes_key.data(), kAesKeySize128, round_keys_.data());
  AesniKeyExpansion128(round_keys_.data());

  SetSetupIsReady();

  if constexpr (kDebug) {
    communication_layer_.GetLogger()->LogDebug(
        "Finished evaluating setup phase of ThreeHalvesEvaluatorProvider");
  }
}

std::unique_ptr<garbled_circuit::Provider> Provider::MakeProvider(
    communication::CommunicationLayer& communication_layer) {
  assert(communication_layer.GetMyId() == static_cast<std::size_t>(GarbledCircuitRole::kGarbler) ||
         communication_layer.GetMyId() == static_cast<std::size_t>(GarbledCircuitRole::kEvaluator));
  if (communication_layer.GetMyId() == static_cast<std::size_t>(GarbledCircuitRole::kGarbler)) {
    return std::make_unique<ThreeHalvesGarblerProvider>(communication_layer);
  } else {
    return std::make_unique<ThreeHalvesEvaluatorProvider>(communication_layer);
  }
}

std::shared_ptr<garbled_circuit::InputGate> Provider::MakeInputGate(std::size_t input_owner_id,
                                                                    std::size_t number_of_wires,
                                                                    std::size_t number_of_simd,
                                                                    Backend& backend) {
  assert(backend.GetCommunicationLayer().GetMyId() ==
             static_cast<std::size_t>(GarbledCircuitRole::kGarbler) ||
         backend.GetCommunicationLayer().GetMyId() ==
             static_cast<std::size_t>(GarbledCircuitRole::kEvaluator));
  if (backend.GetCommunicationLayer().GetMyId() ==
      static_cast<std::size_t>(GarbledCircuitRole::kGarbler)) {
    return backend.GetRegister()->EmplaceGate<InputGateGarbler>(input_owner_id, number_of_wires,
                                                                number_of_simd, backend);
  } else {
    return backend.GetRegister()->EmplaceGate<InputGateEvaluator>(input_owner_id, number_of_wires,
                                                                  number_of_simd, backend);
  }
}

void Provider::AesNiFixedKeyForThreeHalvesGatesBatch3(std::span<const std::byte> round_keys,
                                                      const Block128& hash_key,
                                                      std::size_t gate_index,
                                                      std::span<Block128> input) {
  for (auto& block : input) block ^= hash_key;
  AesniTmmoBatch3(round_keys.data(), input.data(), gate_index);
}

std::shared_ptr<garbled_circuit::AndGate> ThreeHalvesGarblerProvider::MakeAndGate(
    motion::SharePointer parent_a, motion::SharePointer parent_b) {
  assert(parent_a->GetBackend().GetCommunicationLayer().GetMyId() ==
         static_cast<std::size_t>(GarbledCircuitRole::kGarbler));
  return parent_a->GetRegister()->EmplaceGate<AndGateGarbler>(parent_a, parent_b);
}

std::shared_ptr<garbled_circuit::InvGate> ThreeHalvesGarblerProvider::MakeInvGate(
    motion::SharePointer parent) {
  assert(parent->GetBackend().GetCommunicationLayer().GetMyId() ==
         static_cast<std::size_t>(GarbledCircuitRole::kGarbler));
  return parent->GetRegister()->EmplaceGate<InvGateGarbler>(parent);
}

std::shared_ptr<garbled_circuit::XorGate> ThreeHalvesGarblerProvider::MakeXorGate(
    motion::SharePointer parent_a, motion::SharePointer parent_b) {
  assert(parent_a->GetBackend().GetCommunicationLayer().GetMyId() ==
         static_cast<std::size_t>(GarbledCircuitRole::kGarbler));
  return parent_a->GetRegister()->EmplaceGate<XorGateGarbler>(parent_a, parent_b);
}

std::shared_ptr<garbled_circuit::AndGate> ThreeHalvesEvaluatorProvider::MakeAndGate(
    motion::SharePointer parent_a, motion::SharePointer parent_b) {
  assert(parent_a->GetBackend().GetCommunicationLayer().GetMyId() ==
         static_cast<std::size_t>(GarbledCircuitRole::kEvaluator));
  return parent_a->GetRegister()->EmplaceGate<AndGateEvaluator>(parent_a, parent_b);
}

std::shared_ptr<garbled_circuit::InvGate> ThreeHalvesEvaluatorProvider::MakeInvGate(
    motion::SharePointer parent) {
  assert(parent->GetBackend().GetCommunicationLayer().GetMyId() ==
         static_cast<std::size_t>(GarbledCircuitRole::kEvaluator));
  return parent->GetRegister()->EmplaceGate<InvGateEvaluator>(parent);
}

std::shared_ptr<garbled_circuit::XorGate> ThreeHalvesEvaluatorProvider::MakeXorGate(
    motion::SharePointer parent_a, motion::SharePointer parent_b) {
  assert(parent_a->GetBackend().GetCommunicationLayer().GetMyId() ==
         static_cast<std::size_t>(GarbledCircuitRole::kEvaluator));
  return parent_a->GetRegister()->EmplaceGate<XorGateEvaluator>(parent_a, parent_b);
}

ThreeHalvesGarblerProvider::ThreeHalvesGarblerProvider(
    communication::CommunicationLayer& communication_layer)
    : Provider(communication_layer), random_key_offset_(Block128::MakeRandom()) {
  BitSpan random_key_offset_span(random_key_offset_.data(), kKappa);
  // Set 1 at the position of the permutation bit.
  random_key_offset_span.Set(true, kKappa - 1);
  // Truncate both halves by one bit to not destroy control bits in further computations.
  random_key_offset_span.Set(false, 0);
  random_key_offset_span.Set(false, kGarbledRowBitSize);

  public_data_.hash_key = Block128::MakeRandom();
  reinterpret_cast<Block128*>(round_keys_.data())->SetToRandom();
  AesniKeyExpansion128(round_keys_.data());
}

inline void Xor64BitsIntoLeft(void* result, const void* x) {
  *reinterpret_cast<std::uint64_t* __restrict__>(__builtin_assume_aligned(result, 8)) ^=
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x, 8));
}

inline void Xor64BitsIntoLeft(void* result, const void* x0, const void* x1) {
  *reinterpret_cast<std::uint64_t* __restrict__>(__builtin_assume_aligned(result, 8)) ^=
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x0, 8)) ^
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x1, 8));
}

inline void Xor64BitsIntoLeft(void* result, const void* x0, const void* x1, const void* x2) {
  *reinterpret_cast<std::uint64_t* __restrict__>(__builtin_assume_aligned(result, 8)) ^=
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x0, 8)) ^
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x1, 8)) ^
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x2, 8));
}

inline void Xor64BitsIntoLeft(void* result, const void* x0, const void* x1, const void* x2,
                              const void* x3) {
  *reinterpret_cast<std::uint64_t* __restrict__>(__builtin_assume_aligned(result, 8)) ^=
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x0, 8)) ^
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x1, 8)) ^
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x2, 8)) ^
      *reinterpret_cast<const std::uint64_t* __restrict__>(__builtin_assume_aligned(x3, 8));
}

inline void CopyGarbledControlBits(std::byte* data, std::byte garbled_control_bits,
                                   std::size_t bit_offset) {
  std::size_t garbled_control_bits_byte_offset{bit_offset / 8};
  std::size_t garbled_control_bits_local_bit_offset{bit_offset % 8};
  {
    std::byte* data_with_offset{data + garbled_control_bits_byte_offset};
    *data_with_offset |= garbled_control_bits << garbled_control_bits_local_bit_offset;
    bool next_byte_affected{garbled_control_bits_local_bit_offset > 3};
    // xor zero to the same byte if control bits fit into one byte to avoid branching
    // TODO: not sure, if this is more efficient, needs to be tested
    std::byte* target_byte{next_byte_affected ? (data_with_offset + 1) : data_with_offset};
    std::byte payload{next_byte_affected
                          ? garbled_control_bits >> (8 - garbled_control_bits_local_bit_offset)
                          : std::byte(0)};
    *target_byte |= payload;
  }
}

template <std::size_t index>
inline bool GetBit(std::uint64_t x) {
  static_assert(index < 64, "std::uint64_t contains 64 bits indexed from 0 to 63");
  std::uint64_t bit_mask = 1;
  bit_mask <<= index;
  return (x & bit_mask) == bit_mask;
}

inline bool GetLsb(std::uint64_t x) { return (x & 1) == 1; }
#include <string>
template <std::size_t index>
inline bool GetBit(std::byte x) {
  static_assert(index < 8, "std::byte contains 8 bits indexed from 0 to 7");
  return (x & kSetBitMask[index]) == kSetBitMask[index];
}

inline void SetZerothBit(std::uint64_t& result, bool bit) {
  result &= ~std::uint64_t(1);
  result |= static_cast<std::uint64_t>(bit);
}

inline void CopyControlBitsToZerothPositions(std::array<std::uint64_t, 8>& R_times_wires,
                                             std::byte compressed_wire_mapping) {
  SetZerothBit(R_times_wires[0], GetBit<0>(compressed_wire_mapping));
  SetZerothBit(R_times_wires[1], GetBit<1>(compressed_wire_mapping));
  SetZerothBit(R_times_wires[2], GetBit<2>(compressed_wire_mapping));
  SetZerothBit(R_times_wires[3], GetBit<3>(compressed_wire_mapping));
  SetZerothBit(R_times_wires[4], GetBit<4>(compressed_wire_mapping));
  SetZerothBit(R_times_wires[5], GetBit<5>(compressed_wire_mapping));
  SetZerothBit(R_times_wires[6], GetBit<6>(compressed_wire_mapping));
  SetZerothBit(R_times_wires[7], GetBit<7>(compressed_wire_mapping));
}

void ThreeHalvesGarblerProvider::Garble(const Block128Vector& keys_a, const Block128Vector& keys_b,
                                        Block128Vector& keys_out, std::byte* garbled_tables,
                                        std::byte* garbled_control_bits, std::size_t table_offset,
                                        std::size_t gate_index) {
  static_assert(kGarbledControlBitsBitSize == 5, "Garbling may not work for other bit-lengths");
  static_assert(kGarbledRowBitSize == 64, "Garbling may not work for other bit-lengths");
  const std::size_t number_of_simd{keys_a.size()};
  keys_out.resize(number_of_simd);

  auto randomness_pool_for_R{BitVector<>::SecureRandom(2 * number_of_simd)};

  for (std::size_t simd_i = 0; simd_i < number_of_simd; ++simd_i) {
    bool p_a{GetBit<7>(keys_a[simd_i].data()[Block128::kBlockSize - 1])};
    bool p_b{GetBit<7>(keys_b[simd_i].data()[Block128::kBlockSize - 1])};
    // compute "zero keys"
    Block128 key_a_0{p_a ? keys_a[simd_i] ^ random_key_offset_ : keys_a[simd_i]};
    Block128 key_b_0{p_b ? keys_b[simd_i] ^ random_key_offset_ : keys_b[simd_i]};
    //  Sample compressed wire mapping r
    //  Decoded by multiplying with
    //  S1 = | 1 1 | 1 0 |   and   S2 = | 1 0 | 0 1 |
    //       | 1 0 | 0 1 |              | 0 1 | 1 1 |
    std::size_t random_choice_for_R{(randomness_pool_for_R[simd_i * 2] ? 2u : 0u) ^
                                    (randomness_pool_for_R[simd_i * 2 + 1] ? 1u : 0u)};
    std::byte compressed_wire_mapping{SampleWireMapping(p_a, p_b, random_choice_for_R)};

    auto address_of_one_in_truth_table{static_cast<std::size_t>(3 ^ (p_a ? 2 : 0) ^ (p_b ? 1 : 0))};

    // Compute V^-1 * ( r || ( R ^ [ 0 ... 0 | t ] ) * [ A_0 B_0 offset ]^T ),
    // which is the left-hand side of the right part of the equation
    alignas(sizeof(std::uint64_t)) std::array<std::uint64_t, 8> R_times_wires = {0};

    // Precopmute all possible decodings (including the invalid ones, since there are only few)
    static constexpr std::array decoding_lut{GenerateLutForDecoding()};

    auto lut_index{static_cast<std::size_t>(compressed_wire_mapping)};
    // Store 4 left-most columns of R
    std::array partial_R{decoding_lut[lut_index]};

    // R_p = | 0 0 | 1 0 | 0 0 |
    //       | 0 1 | 0 0 | 0 0 |
    //       | 0 0 | 1 0 | 1 0 |
    //       | 0 0 | 0 0 | 0 0 |
    //       | 0 0 | 0 0 | 0 0 |
    //       | 0 1 | 0 0 | 0 1 |
    //       | 0 0 | 0 0 | 0 0 |
    //       | 0 0 | 0 0 | 0 0 |
    static constexpr std::array<std::byte, 4> partial_R_p = {
        std::byte(0b00100100), std::byte(0b00000100), std::byte(0b00100000), std::byte(0)};
    std::transform(partial_R_p.begin(), partial_R_p.end(), partial_R.begin(), partial_R.begin(),
                   std::bit_xor<std::byte>());
    alignas(sizeof(std::uint64_t)) constexpr std::array<std::byte, kGarbledRowByteSize> zero_array =
        {std::byte(0)};

    // Compute  R * [ A_0 B_0 offset ]^T and XOR t * [ A_0 B_0 offset ]^T afterwards on top
    for (std::size_t i = 0; i < 4u; ++i) {
      const std::byte* data_a_left_0{GetBit<0>(partial_R[i]) ? key_a_0.data() : zero_array.data()};
      const std::byte* data_a_right_0{GetBit<1>(partial_R[i]) ? key_a_0.data() + kGarbledRowByteSize
                                                              : zero_array.data()};
      const std::byte* data_b_left_0{GetBit<2>(partial_R[i]) ? key_b_0.data() : zero_array.data()};
      const std::byte* data_b_right_0{GetBit<3>(partial_R[i]) ? key_b_0.data() + kGarbledRowByteSize
                                                              : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[i * 2], data_a_left_0, data_a_right_0, data_b_left_0,
                        data_b_right_0);

      const std::byte* data_a_left_1{GetBit<4>(partial_R[i]) ? key_a_0.data() : zero_array.data()};
      const std::byte* data_a_right_1{GetBit<5>(partial_R[i]) ? key_a_0.data() + kGarbledRowByteSize
                                                              : zero_array.data()};
      const std::byte* data_b_left_1{GetBit<6>(partial_R[i]) ? key_b_0.data() : zero_array.data()};
      const std::byte* data_b_right_1{GetBit<7>(partial_R[i]) ? key_b_0.data() + kGarbledRowByteSize
                                                              : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[i * 2 + 1], data_a_left_1, data_a_right_1, data_b_left_1,
                        data_b_right_1);
    }

    auto offset_left_data{random_key_offset_.data()};
    auto offset_right_data{random_key_offset_.data() + kGarbledRowByteSize};

    // XOR last two columns manually to avoid re-copying BitVector, since they are just
    // duplicates except the very last (bottom right) 2x2 square. First two rows are always
    // zeros.

    // Note: let's stick to the counting starting from 0.
    // Row 2. R_01B.
    {
      const auto choice_left{GetBit<2>(partial_R[1]) ? offset_left_data : zero_array.data()};
      const auto choice_right{GetBit<3>(partial_R[1]) ? offset_right_data : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[2], choice_left, choice_right);
    }
    // Row 3. R_01B.
    {
      const auto choice_left{GetBit<6>(partial_R[1]) ? offset_left_data : zero_array.data()};
      const auto choice_right{GetBit<7>(partial_R[1]) ? offset_right_data : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[3], choice_left, choice_right);
    }
    // Row 4. R_10A.
    {
      const auto choice_left{GetBit<0>(partial_R[2]) ? offset_left_data : zero_array.data()};
      const auto choice_right{GetBit<1>(partial_R[2]) ? offset_right_data : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[4], choice_left, choice_right);
    }
    // Row 5. R_10A.
    {
      const auto choice_left{GetBit<4>(partial_R[2]) ? offset_left_data : zero_array.data()};
      const auto choice_right{GetBit<5>(partial_R[2]) ? offset_right_data : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[5], choice_left, choice_right);
    }
    // Row 6. R_11A ^ R_11B.
    {
      bool flag_left = GetBit<0>(partial_R[3]) != GetBit<2>(partial_R[3]);
      bool flag_right = GetBit<1>(partial_R[3]) != GetBit<3>(partial_R[3]);
      const auto choice_left{flag_left ? offset_left_data : zero_array.data()};
      const auto choice_right{flag_right ? offset_right_data : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[6], choice_left, choice_right);
    }
    // Row 7. R_11A ^ R_11B.
    {
      bool flag_left = GetBit<4>(partial_R[3]) != GetBit<6>(partial_R[3]);
      bool flag_right = GetBit<5>(partial_R[3]) != GetBit<7>(partial_R[3]);
      const auto choice_left{flag_left ? offset_left_data : zero_array.data()};
      const auto choice_right{flag_right ? offset_right_data : zero_array.data()};
      Xor64BitsIntoLeft(&R_times_wires[7], choice_left, choice_right);
    }

    // XOR truth table-related offsets - truth table changes exactly two bits in the table,
    // namely in the last two columns, so we can just use their address to XOR parts of the
    // offset at the right places in constant time

    Xor64BitsIntoLeft(&R_times_wires[address_of_one_in_truth_table * 2], offset_left_data);
    Xor64BitsIntoLeft(&R_times_wires[address_of_one_in_truth_table * 2 + 1], offset_right_data);

    // add r to R * [ A B offset ]^T as 0th bit
    CopyControlBitsToZerothPositions(R_times_wires, compressed_wire_mapping);

    // Compute V^-1 _*_ ( R * [ A B offset ]^T )
    // Inlined:
    // V^-1 = | 1 0 | 0 0 | 0 0 | 0 0 |
    //        | 0 1 | 0 0 | 0 0 | 0 0 |
    //        | 1 1 | 0 0 | 1 1 | 0 0 |
    //        | 1 1 | 1 1 | 0 0 | 0 0 |
    //        | 0 0 | 0 0 | 1 0 | 1 0 |
    // TODO: can the last column be ignored in the computation completely?
    std::array<std::uint64_t, 5> result{R_times_wires[0], R_times_wires[1], R_times_wires[0],
                                        R_times_wires[0], R_times_wires[4]};

    Xor64BitsIntoLeft(&result[2], &R_times_wires[1], &R_times_wires[4], &R_times_wires[5]);
    Xor64BitsIntoLeft(&result[3], &R_times_wires[1], &R_times_wires[2], &R_times_wires[3]);
    Xor64BitsIntoLeft(&result[4], &R_times_wires[6]);

    // Compute H(A_0), H(A_1), H(B_0), H(B_1), H(A_0 ^ B_0), H(A_0 ^ B_1)
    std::array<Block128, 6> hash_inputs = {
        key_a_0,           key_a_0 ^ random_key_offset_,
        key_b_0,           key_b_0 ^ random_key_offset_,
        key_a_0 ^ key_b_0, key_a_0 ^ key_b_0 ^ random_key_offset_};
    // compute AES in-place
    AesNiFixedKeyForThreeHalvesGatesBatch6(round_keys_, public_data_.hash_key, gate_index + simd_i,
                                           hash_inputs);

    // V^-1 * M * H = | 1 0 | 0 0 | 1 0 |  * H = | H(A_0) ^ H(A_0 ^ B_0)                |
    //                | 0 0 | 1 0 | 1 0 |        | H(B_0) ^ H(A_0 ^ B_0)                |
    //                | 1 1 | 0 0 | 0 0 |        | H(A_0) ^ H(A_0 ^ offset)             |
    //                | 0 0 | 1 1 | 0 0 |        | H(B_0) ^ H(B_0 ^ offset)             |
    //                | 0 0 | 0 0 | 1 1 |        | H(A_0 ^ B_0) ^ H(A_0 ^ B_0 ^ offset) |

    // Right-hand side of the right part of the equation
    Xor64BitsIntoLeft(&result[0], hash_inputs[0].data(), hash_inputs[4].data());
    Xor64BitsIntoLeft(&result[1], hash_inputs[2].data(), hash_inputs[4].data());
    Xor64BitsIntoLeft(&result[2], hash_inputs[0].data(), hash_inputs[1].data());
    Xor64BitsIntoLeft(&result[3], hash_inputs[2].data(), hash_inputs[3].data());
    Xor64BitsIntoLeft(&result[4], hash_inputs[4].data(), hash_inputs[5].data());

    // compute z = V^-1 (r ^ vector_lsb(H))

    // effectively, appends LSBs from `result` to `garbled_control_bits`, but "in-place"
    std::byte garbled_control_bits_simd_i{(GetLsb(result[0]) ? std::byte(1) : std::byte(0)) ^
                                          (GetLsb(result[1]) ? std::byte(2) : std::byte(0)) ^
                                          (GetLsb(result[2]) ? std::byte(4) : std::byte(0)) ^
                                          (GetLsb(result[3]) ? std::byte(8) : std::byte(0)) ^
                                          (GetLsb(result[4]) ? std::byte(16) : std::byte(0))};

    std::size_t garbled_control_bits_bit_offset{(table_offset + simd_i) *
                                                kGarbledControlBitsBitSize};
    CopyGarbledControlBits(garbled_control_bits, garbled_control_bits_simd_i,
                           garbled_control_bits_bit_offset);

    // remove 0th bit
    for (auto& x : result) x &= ~std::uint64_t(1);

    std::copy_n(reinterpret_cast<const std::byte*>(&result[0]), 2 * kGarbledRowByteSize,
                keys_out[simd_i].data());

    std::copy_n(reinterpret_cast<std::byte*>(&result[2]), kGarbledTableByteSize,
                garbled_tables + (table_offset + simd_i) * kGarbledTableByteSize);
  }
}

void ThreeHalvesGarblerProvider::AesNiFixedKeyForThreeHalvesGatesBatch6(
    std::span<const std::byte> round_keys, const Block128& hash_key, std::size_t gate_index,
    std::span<Block128> input) {
  for (auto& block : input) block ^= hash_key;
  AesniTmmoBatch6(round_keys.data(), input.data(), gate_index);
}

inline std::byte ExtractGarbledControlBits(const std::byte* data, std::size_t bit_offset) {
  std::size_t control_bits_byte_local_bit_offset{bit_offset % 8};
  std::size_t control_bits_byte_offset{bit_offset / 8};
  std::size_t next_bit_remainder{5 - (8 - control_bits_byte_local_bit_offset)};
  std::byte z{data[control_bits_byte_offset] >> control_bits_byte_local_bit_offset};
  z ^= control_bits_byte_local_bit_offset > 3
           ? (data[control_bits_byte_offset + 1] & TruncationBitMask[next_bit_remainder])
                 << (8 - control_bits_byte_local_bit_offset)
           : std::byte(0);
  return z;
}

void ThreeHalvesEvaluatorProvider::Evaluate(const Block128Vector& keys_a,
                                            const Block128Vector& keys_b, Block128Vector& keys_out,
                                            const std::byte* garbled_tables,
                                            const std::byte* garbled_control_bits,
                                            std::size_t table_offset, std::size_t gate_index) {
  const std::size_t number_of_simd{keys_a.size()};
  keys_out.resize(number_of_simd);
  for (std::size_t simd_i = 0; simd_i < number_of_simd; ++simd_i) {
    std::byte z{ExtractGarbledControlBits(garbled_control_bits,
                                          (table_offset + simd_i) * kGarbledControlBitsBitSize)};

    auto garbled_table_ptr_offset_simd{reinterpret_cast<const std::uint64_t*>(
        garbled_tables + (table_offset + simd_i) * kGarbledTableByteSize)};
    std::uint64_t garbled_row_2(*garbled_table_ptr_offset_simd);
    std::uint64_t garbled_row_3(*(garbled_table_ptr_offset_simd + 1));
    std::uint64_t garbled_row_4(*(garbled_table_ptr_offset_simd + 2));

    // lsbs of the garbled rows should be empty
    assert(BitSpan(reinterpret_cast<std::byte*>(&garbled_row_2), 1)[0] == false);
    assert(BitSpan(reinterpret_cast<std::byte*>(&garbled_row_3), 1)[0] == false);
    assert(BitSpan(reinterpret_cast<std::byte*>(&garbled_row_4), 1)[0] == false);

    // copy last 3 garbled control bits to the garbled rows
    SetZerothBit(garbled_row_2, GetBit<2>(z));
    SetZerothBit(garbled_row_3, GetBit<3>(z));
    SetZerothBit(garbled_row_4, GetBit<4>(z));

    // write down permutation bits
    bool p_a{GetBit<7>(keys_a[simd_i].data()[Block128::kBlockSize - 1])};
    bool p_b{GetBit<7>(keys_b[simd_i].data()[Block128::kBlockSize - 1])};
    auto permutation{static_cast<std::uint8_t>((p_a ? 2 : 0) + (p_b ? 1 : 0))};
    alignas(sizeof(std::uint64_t)) std::array<std::uint64_t, 2> left_part = {0};

    // Compute r || X_ij = V_ij * (z || [ 0 0 G_0 G_1 G_2 ]^T)

    // Next 6 lines are done for all branches
    // left_part[0] = 0;     garbled_row_0, done in the initialization of `left_part`
    // left_part[1] = 0;     garbled_row_1, done in the initialization of `left_part`

    SetZerothBit(left_part[0], GetBit<0>(z));
    SetZerothBit(left_part[1], GetBit<1>(z));
    switch (permutation) {
      case 0:
        // V_00 = | 1 0 0 0 0 |
        //        | 0 1 0 0 0 |
        break;
      case 1:
        // V_01 = | 1 0 0 0 1 |
        //        | 0 1 0 1 1 |
        Xor64BitsIntoLeft(&left_part[0], &garbled_row_4);
        Xor64BitsIntoLeft(&left_part[1], &garbled_row_3, &garbled_row_4);
        break;
      case 2:
        // V_10 = | 1 0 1 0 1 |
        //        | 0 1 0 0 1 |
        Xor64BitsIntoLeft(&left_part[0], &garbled_row_2, &garbled_row_4);
        Xor64BitsIntoLeft(&left_part[1], &garbled_row_4);
        break;
      case 3:
        // V_11 = | 1 0 1 0 0 |
        //        | 0 1 0 1 0 |
        Xor64BitsIntoLeft(&left_part[0], &garbled_row_2);
        Xor64BitsIntoLeft(&left_part[1], &garbled_row_3);
        break;
    }

    // Compute H = H(A), H(B), H(A ^ B)
    std::array<Block128, 3> hash_inputs = {keys_a[simd_i], keys_b[simd_i],
                                           keys_a[simd_i] ^ keys_b[simd_i]};
    // compute AES in-place
    AesNiFixedKeyForThreeHalvesGatesBatch3(round_keys_, public_data_.hash_key, gate_index + simd_i,
                                           hash_inputs);

    // Inline computation of | 1 0 1 | * H
    //                       | 0 1 1 |

    Xor64BitsIntoLeft(&left_part[0], hash_inputs[0].data(), hash_inputs[2].data());
    Xor64BitsIntoLeft(&left_part[1], hash_inputs[1].data(), hash_inputs[2].data());

    // Decode (compressed) r_ij to (decompressed) R_ij
    std::byte R_ij{DecodeCompressedWireMapping(GetBit<0>(left_part[0]), GetBit<0>(left_part[1]))};

    // Apply R_p_ij
    // R_p = | 0 0 | 1 0 | 0 0 |
    //       | 0 1 | 0 0 | 0 0 |
    //       | 0 0 | 1 0 | 1 0 |
    //       | 0 0 | 0 0 | 0 0 |
    //       | 0 0 | 0 0 | 0 0 |
    //       | 0 1 | 0 0 | 0 1 |
    //       | 0 0 | 0 0 | 0 0 |
    //       | 0 0 | 0 0 | 0 0 |
    static constexpr std::array<std::byte, 4> partial_R_p = {
        std::byte(0b00100100), std::byte(0b00000100), std::byte(0b00100000), std::byte(0)};
    R_ij ^= partial_R_p[permutation];
    // Set r_ij bits in X_ij to zeros
    left_part[0] &= ~std::uint64_t(1);
    left_part[1] &= ~std::uint64_t(1);

    alignas(sizeof(std::uint64_t)) constexpr std::array<std::byte, kGarbledRowByteSize> zero_array =
        {std::byte(0)};

    std::array<const std::byte*, 4> data_ptrs_for_R_ij_row;
    // Compute first row of R_ij * [ A B ]^T
    {
      data_ptrs_for_R_ij_row[0] = GetBit<0>(R_ij) ? keys_a[simd_i].data() : zero_array.data();
      data_ptrs_for_R_ij_row[1] =
          GetBit<1>(R_ij) ? keys_a[simd_i].data() + kGarbledRowByteSize : zero_array.data();
      data_ptrs_for_R_ij_row[2] = GetBit<2>(R_ij) ? keys_b[simd_i].data() : zero_array.data();
      data_ptrs_for_R_ij_row[3] =
          GetBit<3>(R_ij) ? keys_b[simd_i].data() + kGarbledRowByteSize : zero_array.data();
      Xor64BitsIntoLeft(&left_part[0], data_ptrs_for_R_ij_row[0], data_ptrs_for_R_ij_row[1],
                        data_ptrs_for_R_ij_row[2], data_ptrs_for_R_ij_row[3]);
    }

    // Compute second row of R_ij * [ A B ]^T
    {
      data_ptrs_for_R_ij_row[0] = GetBit<4>(R_ij) ? keys_a[simd_i].data() : zero_array.data();
      data_ptrs_for_R_ij_row[1] =
          GetBit<5>(R_ij) ? keys_a[simd_i].data() + kGarbledRowByteSize : zero_array.data();
      data_ptrs_for_R_ij_row[2] = GetBit<6>(R_ij) ? keys_b[simd_i].data() : zero_array.data();
      data_ptrs_for_R_ij_row[3] =
          GetBit<7>(R_ij) ? keys_b[simd_i].data() + kGarbledRowByteSize : zero_array.data();

      Xor64BitsIntoLeft(&left_part[1], data_ptrs_for_R_ij_row[0], data_ptrs_for_R_ij_row[1],
                        data_ptrs_for_R_ij_row[2], data_ptrs_for_R_ij_row[3]);
    }
    // Copy both parts of the computed wire label to the wire data
    std::copy_n(reinterpret_cast<const std::byte*>(left_part.data()), 2 * kGarbledRowByteSize,
                keys_out[simd_i].data());
  }
}

ThreeHalvesEvaluatorProvider::ThreeHalvesEvaluatorProvider(
    communication::CommunicationLayer& communication_layer)
    : Provider(communication_layer) {
  three_halves_public_data_future_ = communication_layer.GetMessageManager().RegisterReceive(
      static_cast<std::size_t>(GarbledCircuitRole::kGarbler),
      communication::MessageType::kGarbledCircuitSetup, 0);
}

}  // namespace encrypto::motion::proto::garbled_circuit
