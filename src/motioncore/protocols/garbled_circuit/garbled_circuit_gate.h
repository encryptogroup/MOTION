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

#include <limits>
#include <span>
#include <variant>

#include "base/backend.h"
#include "communication/communication_layer.h"
#include "garbled_circuit_share.h"
#include "garbled_circuit_wire.h"
#include "protocols/gate.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/config.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

class GOt128Receiver;
class GOt128Sender;

namespace proto {

class ConstantBooleanShare;

}

}  // namespace encrypto::motion

namespace encrypto::motion::proto::garbled_circuit {

class InputGate : public motion::InputGate {
 public:
  using Base = motion::InputGate;
  using ValueType = std::vector<BitVector<>>;

  InputGate(std::size_t input_owner_id, std::size_t number_of_wires, std::size_t number_of_simd,
            Backend& backend);

  /// \returns A ReusableFiberPromise that can be used to pass the plaintext inputs.
  ReusableFiberPromise<ValueType>& GetInputPromise();

  /// \brief Interprets output wires as a garbled circuit share.
  ///
  /// Makes a copy of and dynamic_casts the wires, and create a share from those.
  const SharePointer GetOutputAsGarbledCircuitShare();

  ~InputGate() override = default;

 protected:
  /// Number of SIMD values on wires (for delayed or other parties' inputs).
  const std::size_t number_of_simd_;
  /// Number of wires (for delayed or other parties' inputs).
  const std::size_t number_of_wires_;
  /// Indicates if this party owns the input.
  const bool is_my_input_;

  /// Input promise-future pair for own inputs. The corresponding routines will wait for the future
  /// and expect that the future object exists and is valid.
  std::optional<std::pair<ReusableFiberPromise<ValueType>, ReusableFiberFuture<ValueType>>>
      input_promise_future_;
};

class InputGateGarbler final : public garbled_circuit::InputGate {
  using Base = garbled_circuit::InputGate;
  using ValueType = std::vector<BitVector<>>;

 public:
  /// \brief Allocate space for wires but don't pass input values.
  ///
  /// To pass the inputs, the GetInputPromise must be called to obtain a ReusableFiberPromise. This
  /// gate will wait in EvaluateOnline for input_future_.
  /// \see GetInputPromise()
  InputGateGarbler(std::size_t input_owner_id, std::size_t number_of_wires,
                   std::size_t number_of_simd, Backend& backend);

  /// \brief Copy constructor.
  ///
  /// Since Inputs are known here, this constructor internally passes them via \p input_promise_.
  InputGateGarbler(std::span<const BitVector<>> input, std::size_t input_owner_id,
                   Backend& backend);

  /// \brief Move constructor.
  ///
  /// Since Inputs are known here, this constructor internally passes them via \p input_promise_.
  InputGateGarbler(std::vector<BitVector<>>&& input, std::size_t input_owner_id, Backend& backend);

  ~InputGateGarbler() override = default;

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;

 private:
  /// Promise is only required if the gate for own input is created.
  std::unique_ptr<GOt128Sender> ots_for_evaluators_inputs_{nullptr};
};

class InputGateEvaluator final : public garbled_circuit::InputGate {
  using Base = garbled_circuit::InputGate;
  using ValueType = std::vector<BitVector<>>;

 public:
  /// \brief Allocate space for wires but don't pass input values.
  ///
  /// To pass the inputs, the GetInputPromise must be called to obtain a ReusableFiberPromise. This
  /// gate will wait in EvaluateOnline for input_future_.
  /// \see GetInputPromise()
  InputGateEvaluator(std::size_t input_owner_id, std::size_t number_of_wires,
                     std::size_t number_of_simd, Backend& backend);

  /// \brief Copy constructor.
  ///
  /// Since Inputs are known here, this constructor internally passes them via \p input_promise_.
  InputGateEvaluator(std::span<const BitVector<>> input, std::size_t input_owner_id,
                     Backend& backend);

  /// \brief Move constructor.
  ///
  /// Since Inputs are known here, this constructor internally passes them via \p input_promise_.
  InputGateEvaluator(std::vector<BitVector<>>&& input, std::size_t input_owner_id,
                     Backend& backend);

  ~InputGateEvaluator() final = default;

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;

 private:
  /// If this is the evaluator's input, the input label is obtained via OT. If this is the garbler's
  /// input, the corresponding label is simply transmitted to the evaluator by the garbler and
  /// retrieved by the evaluator from the future object.
  std::variant<ReusableFiberFuture<std::vector<std::uint8_t>>, std::unique_ptr<GOt128Receiver>>
      label_source_;
};

class OutputGate : public motion::OutputGate {
 public:
  using Base = motion::OutputGate;
  using ValueType = std::vector<BitVector<>>;

  OutputGate(motion::SharePointer parent, std::size_t output_owner = kAll);

  /// \brief Interprets output wires as a constant share.
  ///
  /// Makes a copy of and dynamic_casts the wires, and create a share from those.
  const std::shared_ptr<ConstantBooleanShare> GetOutputAsConstantShare();

  ~OutputGate() override = default;

  bool NeedsSetup() const override { return false; }

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;

 protected:
  /// The id of the output owner.
  const std::size_t output_owner_;
  /// Flag indicating if all parties are the output owners.
  const bool everyones_output_;
  /// Flag indicating if this party is the output owner.
  const bool my_output_;
  /// The output owner retrieves the cleartext output via the output future registered in
  /// MessageHandler.
  std::optional<ReusableFiberFuture<std::vector<std::uint8_t>>> output_future_;
};

class XorGate : public motion::TwoGate {
 public:
  using Base = motion::TwoGate;

  XorGate(motion::SharePointer parent_a, motion::SharePointer parent_b);

  /// \brief Interprets output wires as a garbled circuit share.
  ///
  /// Makes a copy of and dynamic_casts the wires, and create a share from those.
  SharePointer GetOutputAsGarbledCircuitShare() const;

  /// \brief Calls GetOutputAsGarbledCircuitShare() and casts the result to motion::SharePointer.
  encrypto::motion::SharePointer GetOutputAsShare() const;

  ~XorGate() override = default;
};

class XorGateGarbler final : public XorGate {
 public:
  using Base = XorGate;

  XorGateGarbler(motion::SharePointer parent_a, motion::SharePointer parent_b);

  ~XorGateGarbler() override = default;

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  bool NeedsOnline() const override { return false; }

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;
};

class XorGateEvaluator final : public XorGate {
 public:
  using Base = XorGate;

  XorGateEvaluator(motion::SharePointer parent_a, motion::SharePointer parent_b);

  ~XorGateEvaluator() override = default;

  bool NeedsSetup() const override { return false; }

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;
};

class InvGate : public motion::OneGate {
 public:
  using Base = motion::OneGate;
  InvGate() = delete;
  InvGate(const InvGate&) = delete;

  InvGate(motion::SharePointer parent);

  /// \brief Interprets output wires as a garbled circuit share.
  ///
  /// Makes a copy of and dynamic_casts the wires, and create a share from those.
  SharePointer GetOutputAsGarbledCircuitShare() const;

  /// \brief Calls GetOutputAsGarbledCircuitShare() and casts the result to motion::SharePointer.
  encrypto::motion::SharePointer GetOutputAsShare() const;
};

class InvGateGarbler final : public InvGate {
 public:
  using Base = InvGate;

  InvGateGarbler(motion::SharePointer parent);

  ~InvGateGarbler() override = default;

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  bool NeedsOnline() const override { return false; }

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;
};

class InvGateEvaluator final : public InvGate {
 public:
  using Base = InvGate;

  InvGateEvaluator(motion::SharePointer parent);

  ~InvGateEvaluator() override = default;

  bool NeedsSetup() const override { return false; }

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;
};

class AndGate : public motion::TwoGate {
 public:
  using Base = motion::TwoGate;
  AndGate() = delete;
  AndGate(const AndGate&) = delete;

  /// \brief Interprets output wires as a garbled circuit share.
  ///
  /// Makes a copy of and dynamic_casts the wires, and create a share from those.
  SharePointer GetOutputAsGarbledCircuitShare() const;

  /// \brief Calls GetOutputAsGarbledCircuitShare() and casts the result to motion::SharePointer.
  encrypto::motion::SharePointer GetOutputAsShare() const;

 protected:
  AndGate(motion::SharePointer parent_a, motion::SharePointer parent_b);
};

//  /// Index that is used as a tweak in the (T)MMO construction. The wire id cannot be used for
//  this
//  /// because there might be many SIMD wires on a single wire. Provider keeps track of the ids.
//  const std::size_t label_id_offset_;
class AndGateGarbler final : public AndGate {
 public:
  using Base = AndGate;

  AndGateGarbler(motion::SharePointer parent_a, motion::SharePointer parent_b);

  ~AndGateGarbler() override = default;

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  //bool NeedsOnline() const override { return false; }

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;
};

class AndGateEvaluator final : public AndGate {
 public:
  using Base = AndGate;

  AndGateEvaluator(motion::SharePointer parent_a, motion::SharePointer parent_b);

  ~AndGateEvaluator() override = default;

  /// \brief Evaluates the setup phase.
  void EvaluateSetup() override;

  /// \brief Evaluates the online phase.
  void EvaluateOnline() override;

 private:
  ReusableFiberFuture<std::vector<std::uint8_t>> garbled_tables_msg_future_;
};

}  // namespace encrypto::motion::proto::garbled_circuit
