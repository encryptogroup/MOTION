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

#include <mutex>
#include <type_traits>

#include "astra_gate.h"
#include "astra_share.h"
#include "astra_wire.h"
#include "communication/message_manager.h"
#include "primitives/sharing_randomness_generator.h"
#include "utility/helpers.h"

namespace encrypto::motion::proto::astra {

template <typename T>
InputGate<T>::InputGate(std::vector<T> input, std::size_t input_owner, Backend& backend)
    : Base(backend) {
  input_owner_id_ = input_owner;

  auto my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());

  std::shared_ptr<astra::Wire<T>> w;
  std::vector<typename astra::Wire<T>::value_type> d;
  d.reserve(input.size());
  for (auto&& e : input) {
    d.emplace_back(my_id == static_cast<std::int64_t>(input_owner) ? std::move(e) : 0, 0, 0);
  }
  w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(d));

  output_wires_ = {std::move(w)};

  if (my_id != input_owner_id_ && my_id != 0) {
    input_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        input_owner_id_, communication::MessageType::kAstraInputGate, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
                                 input_owner_id_);
    GetLogger().LogDebug(
        fmt::format("Allocate an astra::InputGate with following properties: {}", gate_info));
  }
}

template <typename T>
void InputGate<T>::EvaluateSetup() {
  auto my_id = GetCommunicationLayer().GetMyId();
  GetBaseProvider().WaitSetup();

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();

  switch (input_owner_id_) {
    case 0:
      switch (my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          std::vector<T> randoms1 = rng1.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms2 = rng2.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms1.size() == values.size());
          assert(randoms2.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms1[i];
            v.lambda2 = randoms2[i];
          }
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms0.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms0[i];
          }
          break;
        }
        case 2: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms0.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda2 = randoms0[i];
          }
          break;
        }
      }
      break;
    case 1:
      switch (my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms1 = rng1.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms1.size() == values.size());
          assert(randoms_global.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms1[i];
            v.lambda2 = randoms_global[i];
          }
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms0.size() == values.size());
          assert(randoms_global.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms0[i];
            v.lambda2 = randoms_global[i];
          }
          break;
        }
        case 2: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda2 = randoms_global[i];
          }
          break;
        }
      }
      break;
    case 2:
      switch (my_id) {
        case 0: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms2 = rng2.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms_global.size() == values.size());
          assert(randoms2.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms_global[i];
            v.lambda2 = randoms2[i];
          }
          break;
        }
        case 1: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms_global.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms_global[i];
          }
          break;
        }
        case 2: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms_global.size() == values.size());
          assert(randoms0.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms_global[i];
            v.lambda2 = randoms0[i];
          }
          break;
        }
      }
      break;
  }
  out_wire->SetSetupIsReady();
}

template <typename T>
void InputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();

  if (static_cast<std::size_t>(input_owner_id_) == my_id) {
    std::vector<T> buffer(values.size());
    for (auto i = 0u; i != values.size(); ++i) {
      auto& v = values[i];
      T lambda_x = v.lambda1 + v.lambda2;
      v.value += lambda_x;
      buffer[i] = v.value;
    }

    auto payload = ToByteVector<T>(buffer);
    auto message{communication::BuildMessage(communication::MessageType::kAstraInputGate, gate_id_,
                                             payload)};
    if (my_id == 0) {
      communication_layer.BroadcastMessage(message.Release());
    } else if (my_id == 1) {
      communication_layer.SendMessage(2, message.Release());
    } else if (my_id == 2) {
      communication_layer.SendMessage(1, message.Release());
    }

  } else if (my_id != 0) {
    auto input_message{input_future_.get()};
    auto payload{communication::GetMessage(input_message.data())->payload()};
    auto buffer = FromByteVector<T>({payload->Data(), payload->size()});
    assert(buffer.size() == values.size());
    for (auto i = 0u; i != buffer.size(); ++i) {
      values[i].value = std::move(buffer[i]);
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::InputGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> InputGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class InputGate<std::uint8_t>;
template class InputGate<std::uint16_t>;
template class InputGate<std::uint32_t>;
template class InputGate<std::uint64_t>;
template class InputGate<__uint128_t>;

// TODO: Implement sending output only to one party
template <typename T>
OutputGate<T>::OutputGate(const astra::WirePointer<T>& parent, std::size_t output_owner)
    : Base(parent->GetBackend()) {
  assert(parent);

  if (parent->GetProtocol() != MpcProtocol::kAstra) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(
        std::runtime_error((fmt::format("Astra output gate expects an astra share, "
                                        "got a share of type {}",
                                        sharing_type))));
  }
  auto my_id{static_cast<std::int64_t>(GetCommunicationLayer().GetMyId())};

  parent_ = {parent};
  output_owner_ = output_owner;

  std::vector<typename astra::Wire<T>::value_type> v(parent->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if (output_owner_ == my_id || output_owner_ == kAll) {
    output_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        (my_id + 1) % 3, communication::MessageType::kAstraOutputGate, gate_id_);
  }
}

template <typename T>
OutputGate<T>::OutputGate(const astra::SharePointer<T>& parent, std::size_t output_owner)
    : OutputGate((assert(parent), parent->GetAstraWire()), output_owner) {}

template <typename T>
OutputGate<T>::OutputGate(const motion::SharePointer& parent, std::size_t output_owner)
    : OutputGate(std::dynamic_pointer_cast<astra::Share<T>>(parent), output_owner) {}

template <typename T>
void OutputGate<T>::EvaluateSetup() {
}

template <typename T>
void OutputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_.at(0)->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto in_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_.at(0));
  assert(in_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& in_values = in_wire->GetValues();
  assert(in_values.size() == out_values.size());

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = static_cast<std::int64_t>(communication_layer.GetMyId());

  switch (my_id) {
    case 0: {
      std::vector<T> message_lambda1s(in_values.size());
      for (auto i = 0u; i != message_lambda1s.size(); ++i) {
        message_lambda1s[i] = in_values[i].lambda1;
      }

      // send output message
      if (output_owner_ == 2 || output_owner_ == kAll) {
        auto payload = ToByteVector<T>(message_lambda1s);

        auto message{communication::BuildMessage(communication::MessageType::kAstraOutputGate,
                                                 gate_id_, payload)};
        communication_layer.SendMessage(2, message.Release());
      }

      const auto output_message{output_future_.get()};
      const auto payload{communication::GetMessage(output_message.data())->payload()};
      auto received_values = FromByteVector<T>({payload->Data(), payload->size()});
      assert(received_values.size() == in_values.size());
      for (auto i = 0u; i != received_values.size(); ++i) {
        auto& in = in_values[i];
        out_values[i].value = received_values[i] - in.lambda1 - in.lambda2;
      }
      break;
    }
    case 1: {
      std::vector<T> message_values(in_values.size());
      for (auto i = 0u; i != message_values.size(); ++i) {
        message_values[i] = in_values[i].value;
      }

      if (output_owner_ == 0 || output_owner_ == kAll) {
        auto payload = ToByteVector<T>(message_values);
        auto message{communication::BuildMessage(communication::MessageType::kAstraOutputGate,
                                                 gate_id_, payload)};
        communication_layer.SendMessage(0, message.Release());
      }

      if (output_owner_ == my_id || output_owner_ == kAll) {
        const auto message{output_future_.get()};
        const auto payload{communication::GetMessage(message.data())->payload()};
        auto received_lambda2s = FromByteVector<T>({payload->Data(), payload->size()});
        assert(received_lambda2s.size() == in_values.size());
        for (auto i = 0u; i != received_lambda2s.size(); ++i) {
          auto& in = in_values[i];
          out_values[i].value = in.value - in.lambda1 - received_lambda2s[i];
        }
      }
      break;
    }
    case 2: {
      std::vector<T> message_lambda2s(in_values.size());
      for (auto i = 0u; i != message_lambda2s.size(); ++i) {
        message_lambda2s[i] = in_values[i].lambda2;
      }

      if (output_owner_ == 1 || output_owner_ == kAll) {
        auto payload = ToByteVector<T>(message_lambda2s);
        auto message{communication::BuildMessage(communication::MessageType::kAstraOutputGate,
                                                 gate_id_, payload)};
        communication_layer.SendMessage(1, message.Release());
      }

      if (output_owner_ == my_id || output_owner_ == kAll) {
        const auto message{output_future_.get()};
        const auto payload{communication::GetMessage(message.data())->payload()};
        auto received_lambda1s = FromByteVector<T>({payload->Data(), payload->size()});
        assert(received_lambda1s.size() == in_values.size());
        for (auto i = 0u; i != received_lambda1s.size(); ++i) {
          auto& in = in_values[i];
          out_values[i].value = in.value - received_lambda1s[i] - in.lambda2;
        }
      }
      break;
    }
    default: {
      assert(false);
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::OutputGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> OutputGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class OutputGate<std::uint8_t>;
template class OutputGate<std::uint16_t>;
template class OutputGate<std::uint32_t>;
template class OutputGate<std::uint64_t>;
template class OutputGate<__uint128_t>;

template <typename T>
AdditionGate<T>::AdditionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  assert(a->GetNumberOfSimdValues() == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  std::vector<typename astra::Wire<T>::value_type> v(parent_a_.at(0)->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created an astra::AdditionGate with following properties: {}", gate_info));
  }
}

template <typename T>
void AdditionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  assert(out_values.size() == a_values.size());
  assert(a_values.size() == b_values.size());

  auto my_id = GetCommunicationLayer().GetMyId();

  switch (my_id) {
    case 0: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 + b.lambda1;
        out.lambda2 = a.lambda2 + b.lambda2;
      }
      break;
    }
    case 1: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 + b.lambda1;
      }
      break;
    }
    case 2: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda2 = a.lambda2 + b.lambda2;
      }
      break;
    }
  }
  out_wire->SetSetupIsReady();
}

template <typename T>
void AdditionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  auto my_id = GetCommunicationLayer().GetMyId();

  if (my_id != 0) {
    for (auto i = 0u; i != out_values.size(); ++i) {
      auto& out = out_values[i];
      auto& a = a_values[i];
      auto& b = b_values[i];

      out.value = a.value + b.value;
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::AdditionGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> AdditionGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class AdditionGate<std::uint8_t>;
template class AdditionGate<std::uint16_t>;
template class AdditionGate<std::uint32_t>;
template class AdditionGate<std::uint64_t>;
template class AdditionGate<__uint128_t>;

template <typename T>
SubtractionGate<T>::SubtractionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  assert(a->GetNumberOfSimdValues() == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  std::vector<typename astra::Wire<T>::value_type> v(parent_a_.at(0)->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created an astra::Subtraction with following properties: {}", gate_info));
  }
}

template <typename T>
void SubtractionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  auto my_id = GetCommunicationLayer().GetMyId();

  switch (my_id) {
    case 0: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 - b.lambda1;
        out.lambda2 = a.lambda2 - b.lambda2;
      }
      break;
    }
    case 1: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 - b.lambda1;
      }
      break;
    }
    case 2: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda2 = a.lambda2 - b.lambda2;
      }
      break;
    }
  }

  out_wire->SetSetupIsReady();
}

template <typename T>
void SubtractionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  auto my_id = GetCommunicationLayer().GetMyId();

  if (my_id != 0) {
    for (auto i = 0u; i != out_values.size(); ++i) {
      auto& out = out_values[i];
      auto& a = a_values[i];
      auto& b = b_values[i];

      out.value = a.value - b.value;
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::SubtractionGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> SubtractionGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class SubtractionGate<std::uint8_t>;
template class SubtractionGate<std::uint16_t>;
template class SubtractionGate<std::uint32_t>;
template class SubtractionGate<std::uint64_t>;
template class SubtractionGate<__uint128_t>;

template <typename T>
MultiplicationGate<T>::MultiplicationGate(const astra::WirePointer<T>& a,
                                          const astra::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  assert(a->GetNumberOfSimdValues() == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  std::vector<typename astra::Wire<T>::value_type> v(parent_a_.at(0)->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  std::size_t my_id{GetCommunicationLayer().GetMyId()};
  auto& message_manager{backend_.GetCommunicationLayer().GetMessageManager()};
  if (my_id == 1) {
    multiply_future_online_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAstraOnlineMultiplyGate, gate_id_);
  } else if (my_id == 2) {
    multiply_future_setup_ = message_manager.RegisterReceive(
        0, communication::MessageType::kAstraSetupMultiplyGate, gate_id_);
    multiply_future_online_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAstraOnlineMultiplyGate, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an astra::MultiplicationGate with following properties: {}", gate_info));
  }
}

template <typename T>
void MultiplicationGate<T>::EvaluateSetup() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);

  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();

  auto& out_values = out_wire->GetMutableValues();

  switch (my_id) {
    case 0: {
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      std::vector<T> randoms1 = rng1.template GetUnsigned<T>(gate_id_, 2 * out_values.size());
      std::vector<T> randoms2 = rng2.template GetUnsigned<T>(gate_id_, out_values.size());
      assert(randoms1.size() == 2 * out_values.size());
      assert(randoms2.size() == out_values.size());

      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        out.lambda1 = randoms1[i];
        out.lambda2 = randoms2[i];
      }

      auto const& a_values = a_wire->GetMutableValues();
      auto const& b_values = b_wire->GetMutableValues();

      std::vector<T> message_gamma_ab_2;
      message_gamma_ab_2.reserve(out_values.size());

      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& a = a_values[i];
        auto& b = b_values[i];

        T gamma_ab_1 = randoms1[i + out_values.size()];
        T lambda_a = a.lambda1 + a.lambda2;
        T lambda_b = b.lambda1 + b.lambda2;
        T gamma_ab = lambda_a * lambda_b;
        T gamma_ab_2 = gamma_ab - gamma_ab_1;
        message_gamma_ab_2.emplace_back(std::move(gamma_ab_2));
      }
      assert(message_gamma_ab_2.size() == out_values.size());

      auto payload = ToByteVector<T>(message_gamma_ab_2);
      auto message{communication::BuildMessage(communication::MessageType::kAstraSetupMultiplyGate,
                                               gate_id_, payload)};
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 1: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, 2 * out_values.size());
      assert(randoms0.size() == 2 * out_values.size());

      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        out.lambda1 = randoms0[i];
        // We store gamma_ab_1 in the free out.lambda2 space
        out.lambda2 = randoms0[i + out_values.size()];
      }
      break;
    }
    case 2: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, out_values.size());
      assert(randoms0.size() == out_values.size());

      const auto message{multiply_future_setup_.get()};
      const auto payload{communication::GetMessage(message.data())->payload()};
      std::vector<T> message_gamma_ab_2 = FromByteVector<T>({payload->Data(), payload->size()});
      assert(message_gamma_ab_2.size() == out_values.size());

      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        out.lambda2 = randoms0[i];
        // We store gamma_ab_2 in the free out.lambda1 space
        out.lambda1 = message_gamma_ab_2[i];
      }
      break;
    }
  }

  out_wire->SetSetupIsReady();
}

template <typename T>
void MultiplicationGate<T>::EvaluateOnline() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  if (my_id != 0) {
    switch (my_id) {
      case 1: {
        for (auto i = 0u; i != out_values.size(); ++i) {
          auto& out = out_values[i];
          auto const& a = a_values[i];
          auto const& b = b_values[i];
          auto const& gamma_ab_1 = out.lambda2;

          out.value = -(a.value * b.lambda1) - b.value * a.lambda1 + out.lambda1 + gamma_ab_1;
        }

        std::vector<T> message_values;
        message_values.reserve(out_values.size());
        for (auto i = 0u; i != out_values.size(); ++i) {
          message_values.emplace_back(out_values[i].value);
        }
        assert(message_values.size() == out_values.size());

        {
          auto payload = ToByteVector<T>(message_values);
          auto message{communication::BuildMessage(
              communication::MessageType::kAstraOnlineMultiplyGate, gate_id_, payload)};
          communication_layer.SendMessage(2, message.Release());
        }
        const auto multiply_message{multiply_future_online_.get()};
        const auto payload{communication::GetMessage(multiply_message.data())->payload()};
        message_values = FromByteVector<T>({payload->Data(), payload->size()});
        assert(message_values.size() == out_values.size());

        for (auto i = 0u; i != out_values.size(); ++i) {
          out_values[i].value += message_values[i];
        }
        break;
      }
      case 2: {
        for (auto i = 0u; i != out_values.size(); ++i) {
          auto& out = out_values[i];
          auto const& a = a_values[i];
          auto const& b = b_values[i];
          auto const& gamma_ab_2 = out.lambda1;

          out.value = a.value * b.value - a.value * b.lambda2 - b.value * a.lambda2 + out.lambda2 +
                      gamma_ab_2;
        }

        std::vector<T> message_values;
        message_values.reserve(out_values.size());
        for (auto i = 0u; i != out_values.size(); ++i) {
          message_values.emplace_back(out_values[i].value);
        }
        assert(message_values.size() == out_values.size());

        {
          auto payload = ToByteVector<T>(message_values);
          auto message{communication::BuildMessage(
              communication::MessageType::kAstraOnlineMultiplyGate, gate_id_, payload)};
          communication_layer.SendMessage(1, message.Release());
        }

        const auto message{multiply_future_online_.get()};
        const auto payload{communication::GetMessage(message.data())->payload()};
        message_values = FromByteVector<T>({payload->Data(), payload->size()});
        assert(message_values.size() == out_values.size());

        for (auto i = 0u; i != out_values.size(); ++i) {
          out_values[i].value += message_values[i];
        }
        break;
      }
    }
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::MultiplicationGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> MultiplicationGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class MultiplicationGate<std::uint8_t>;
template class MultiplicationGate<std::uint16_t>;
template class MultiplicationGate<std::uint32_t>;
template class MultiplicationGate<std::uint64_t>;
template class MultiplicationGate<__uint128_t>;

template <typename T>
DotProductGate<T>::DotProductGate(std::vector<motion::WirePointer> vector_a,
                                  std::vector<motion::WirePointer> vector_b)
    : Base((assert(vector_a.size() > 0), assert(vector_a.size() == vector_b.size()),
            vector_a[0]->GetBackend())) {
  parent_a_ = std::move(vector_a);
  parent_b_ = std::move(vector_b);

  auto number_of_simd_values = parent_a_[0]->GetNumberOfSimdValues();

  std::vector<typename astra::Wire<T>::value_type> v(number_of_simd_values);
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  std::size_t my_id{GetCommunicationLayer().GetMyId()};
  auto& message_manager{GetCommunicationLayer().GetMessageManager()};
  if (my_id == 1) {
    dot_product_future_online_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAstraOnlineDotProductGate, gate_id_);
  } else if (my_id == 2) {
    dot_product_future_setup_ = message_manager.RegisterReceive(
        0, communication::MessageType::kAstraSetupDotProductGate, gate_id_);
    dot_product_future_online_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAstraOnlineDotProductGate, gate_id_);
  }
}

template <typename T>
void DotProductGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();

  for (auto i = 0u; i != parent_a_.size(); ++i) {
    auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[i]);
    assert(a_wire);
    auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[i]);
    assert(b_wire);

    a_wire->GetSetupReadyCondition()->Wait();
    b_wire->GetSetupReadyCondition()->Wait();
  }

  switch (my_id) {
    case 0: {
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      std::vector<T> randoms1 = rng1.template GetUnsigned<T>(gate_id_, 2 * out_values.size());
      std::vector<T> randoms2 = rng2.template GetUnsigned<T>(gate_id_, out_values.size());
      assert(randoms1.size() == 2 * out_values.size());
      assert(randoms2.size() == out_values.size());

      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];

        out.lambda1 = randoms1[i];
        out.lambda2 = randoms2[i];
      }

      std::vector<T> message_gamma_ab_2;
      message_gamma_ab_2.reserve(out_values.size());
      for (auto i = 0u; i != out_values.size(); ++i) {
        T gamma_ab_1 = randoms1[i + out_values.size()];
        T gamma_ab{0};

        for (auto j = 0u; j != parent_a_.size(); ++j) {
          auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(j));
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(j));
          assert(b_wire);

          auto const& a = a_wire->GetValues()[i];
          auto const& b = b_wire->GetValues()[i];
          // Compute gamma_ab
          T lambda_a = a.lambda1 + a.lambda2;
          T lambda_b = b.lambda1 + b.lambda2;
          gamma_ab += lambda_a * lambda_b;
        }
        message_gamma_ab_2.emplace_back(gamma_ab - gamma_ab_1);
      }
      assert(message_gamma_ab_2.size() == out_values.size());

      auto payload = ToByteVector<T>(message_gamma_ab_2);
      auto message{communication::BuildMessage(
          communication::MessageType::kAstraSetupDotProductGate, gate_id_, payload)};
      communication_layer.SendMessage(2, std::move(message.Release()));
      break;
    }
    case 1: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, 2 * out_values.size());
      assert(randoms0.size() == 2 * out_values.size());

      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        out.lambda1 = randoms0[i];
        // We store gamma_ab_1 in the free out_lambda space
        out.lambda2 = randoms0[i + out_values.size()];
      }
      break;
    }
    case 2: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, out_values.size());
      assert(randoms0.size() == out_values.size());

      const auto message{dot_product_future_setup_.get()};
      const auto payload{communication::GetMessage(message.data())->payload()};
      std::vector<T> message_gamma_ab_2 = FromByteVector<T>({payload->Data(), payload->size()});
      assert(message_gamma_ab_2.size() == out_values.size());
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        out.lambda2 = randoms0[i];
        // We store gamma_ab_2 in the free out_lambda space
        out.lambda1 = message_gamma_ab_2[i];
      }
      break;
    }
  }

  out_wire->SetSetupIsReady();
}

template <typename T>
void DotProductGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  // using namespace std::literals;

  for (auto i = 0u; i != parent_a_.size(); ++i) {
    parent_a_[i]->GetIsReadyCondition().Wait();
    parent_b_[i]->GetIsReadyCondition().Wait();
  }

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();

  if (my_id != 0) {
    auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
    assert(out_wire);
    auto& out_values = out_wire->GetMutableValues();
    std::vector<T> message_values;
    message_values.reserve(out_values.size());
    for (auto i = 0u; i != out_values.size(); ++i) {
      auto& out = out_values[i];
      out.value = 0u;
      for (auto j = 0u; j != parent_a_.size(); ++j) {
        auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(j));
        assert(a_wire);
        auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(j));
        assert(b_wire);

        auto const& a = a_wire->GetValues()[i];
        auto const& b = b_wire->GetValues()[i];

        switch (my_id) {
          case 1: {
            out.value += -(a.value * b.lambda1) - b.value * a.lambda1;
            break;
          }
          case 2: {
            out.value += a.value * b.value - a.value * b.lambda2 - b.value * a.lambda2;
            break;
          }
          default: {
            assert(false);
          }
        }
      }
      out.value += out.lambda1 + out.lambda2;
      message_values.emplace_back(out.value);
    }
    assert(message_values.size() == out_values.size());

    {
      auto payload = ToByteVector<T>(message_values);

      auto message{communication::BuildMessage(
          communication::MessageType::kAstraOnlineDotProductGate, gate_id_, payload)};
      switch (my_id) {
        case 1: {
          communication_layer.SendMessage(2, message.Release());
          break;
        }
        case 2: {
          communication_layer.SendMessage(1, message.Release());
          break;
        }
        default: {
          assert(false);
        }
      }
    }

    const auto message{dot_product_future_online_.get()};
    const auto payload{communication::GetMessage(message.data())->payload()};
    message_values = FromByteVector<T>({payload->Data(), payload->size()});
    assert(message_values.size() == out_values.size());

    for (auto i = 0u; i != out_values.size(); ++i) {
      out_values[i].value += message_values[i];
    }
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::DotProductGate with id#{}", gate_id_));
  }
}
template <typename T>
astra::SharePointer<T> DotProductGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class DotProductGate<std::uint8_t>;
template class DotProductGate<std::uint16_t>;
template class DotProductGate<std::uint32_t>;
template class DotProductGate<std::uint64_t>;
template class DotProductGate<__uint128_t>;

}  // namespace encrypto::motion::proto::astra
