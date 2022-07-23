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

#pragma once

#include <memory>
#include <unordered_map>

#include "communication/message_manager.h"
#include "garbled_circuit_gate.h"
#include "garbled_circuit_wire.h"
#include "primitives/aes/aesni_primitives.h"
#include "primitives/random/default_rng.h"
#include "utility/block.h"
#include "utility/constants.h"
#include "utility/fiber_waitable.h"
#include "utility/typedefs.h"

namespace encrypto::motion {

class Backend;

namespace communication {
class CommunicationLayer;
}

}  // namespace encrypto::motion

namespace encrypto::motion::proto::garbled_circuit {

// forward declarations
class Wire;
using WirePointer = std::shared_ptr<Wire>;

struct ThreeHalvesGarblingPublicData {
  Block128 hash_key;
  Block128 aes_key;
};

// The garbled circuit provider interface
class Provider : public FiberSetupWaitable {
 public:
  Provider(communication::CommunicationLayer& communication_layer);

  // delete the copy constructor
  Provider(const Provider&) = delete;

  virtual ~Provider() = default;

  virtual void Setup() = 0;

  bool HasWork() { return true; }

  /// \brief Depending on the party's id (obtained from the \p communication_layer) creates either a
  /// ThreeHalvesGarblerProvider or a ThreeHalvesEvaluatorProvider static_casted to their parent.
  static std::unique_ptr<garbled_circuit::Provider> MakeProvider(
      communication::CommunicationLayer& communication_layer);

  /// \brief Constructs an Input gate. An InputGateGarbled is constructed for garbler and an
  /// InputGateEvaluator for the evaluator. The result is static_pointer_cast'ed to
  /// garbled_circuit::InputGate.
  static std::shared_ptr<garbled_circuit::InputGate> MakeInputGate(std::size_t input_owner_id,
                                                                   std::size_t number_of_wires,
                                                                   std::size_t number_of_simd,
                                                                   Backend& backend);

  /// \brief Constructs a specific AND gate using the internal state of the provider, namely the
  /// garbled table offset, which needs to be kept track about separately due to SIMD.
  virtual std::shared_ptr<garbled_circuit::AndGate> MakeAndGate(motion::SharePointer parent_a,
                                                                motion::SharePointer parent_b) = 0;

  /// \brief Constructs a specific INV gate depending on party's role.
  virtual std::shared_ptr<garbled_circuit::InvGate> MakeInvGate(motion::SharePointer parent) = 0;

  /// \brief Constructs a specific XOR gate depending on party's role.
  virtual std::shared_ptr<garbled_circuit::XorGate> MakeXorGate(motion::SharePointer parent_a,
                                                                motion::SharePointer parent_b) = 0;

  void AesNiFixedKeyForThreeHalvesGatesBatch3(std::span<const std::byte> round_keys,
                                              const Block128& hash_key, std::size_t gate_index,
                                              std::span<Block128> input);

 protected:
  communication::CommunicationLayer& communication_layer_;

  std::size_t number_of_garbled_tables_{0};

  alignas(kAesBlockSize) std::array<std::byte, kAesRoundKeysSize128> round_keys_;

  ThreeHalvesGarblingPublicData public_data_;

  std::atomic<bool> preprocessing_done_{false};
};

class ThreeHalvesGarblerProvider final : public Provider {
 public:
  ThreeHalvesGarblerProvider(communication::CommunicationLayer& communication_layer);

  ~ThreeHalvesGarblerProvider() override = default;

  void Setup() override;

  const Block128& GetOffset() const { return random_key_offset_; }

  std::shared_ptr<garbled_circuit::AndGate> MakeAndGate(motion::SharePointer parent_a,
                                                        motion::SharePointer parent_b) override;

  std::shared_ptr<garbled_circuit::InvGate> MakeInvGate(motion::SharePointer parent_a) override;

  std::shared_ptr<garbled_circuit::XorGate> MakeXorGate(motion::SharePointer parent_a,
                                                        motion::SharePointer parent_b) override;

  void Garble(const Block128Vector& keys_a, const Block128Vector& keys_b, Block128Vector& keys_out,
              std::byte*, std::byte* garbled_control_bits,
              std::size_t table_offset, std::size_t gate_index);

  void AesNiFixedKeyForThreeHalvesGatesBatch6(std::span<const std::byte> round_keys,
                                              const Block128& hash_key, std::size_t gate_index,
                                              std::span<Block128> input);

 private:
  Block128 random_key_offset_;
};

class ThreeHalvesEvaluatorProvider final : public Provider {
 public:
  ThreeHalvesEvaluatorProvider(communication::CommunicationLayer& communication_layer);

  ~ThreeHalvesEvaluatorProvider() override = default;

  void Setup() override;

  void Evaluate(const Block128Vector& keys_a, const Block128Vector& keys_b,
                Block128Vector& keys_out, const std::byte* garbled_tables,
                const std::byte* garbled_control_bits, std::size_t table_offset,
                std::size_t gate_index);

  std::shared_ptr<garbled_circuit::AndGate> MakeAndGate(motion::SharePointer parent_a,
                                                        motion::SharePointer parent_b) override;

  std::shared_ptr<garbled_circuit::InvGate> MakeInvGate(motion::SharePointer parent_a) override;

  std::shared_ptr<garbled_circuit::XorGate> MakeXorGate(motion::SharePointer parent_a,
                                                        motion::SharePointer parent_b) override;

 private:
  ReusableFiberFuture<std::vector<std::uint8_t>> three_halves_public_data_future_;
};

}  // namespace encrypto::motion::proto::garbled_circuit
