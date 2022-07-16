// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko
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

#include "subset_gate.h"

#include "base/configuration.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/constant/constant_share.h"
#include "protocols/constant/constant_wire.h"
#include "protocols/share.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

SubsetGate::SubsetGate(const SharePointer& parent, std::vector<std::size_t>&& position_ids)
    : OneGate(parent->GetBackend()), position_ids_(std::move(position_ids)) {
  parent_ = parent->GetWires();

  if constexpr (kDebug) {
    if (parent_.empty()) {
      throw std::invalid_argument(
          fmt::format("Input share in SubsetGate#{} has no wires", gate_id_));
    }
    if (position_ids_.empty()) {
      throw std::invalid_argument(
          fmt::format("The list of position ids in SubsetGate#{} is empty", gate_id_));
    }
  }
  const std::size_t number_of_simd{parent_[0]->GetNumberOfSimdValues()};
  const MpcProtocol protocol{parent_[0]->GetProtocol()};
  if constexpr (kDebug) {
    for (std::size_t i = 1; i < parent_.size(); ++i) {
      if (parent_[i]->GetNumberOfSimdValues() != number_of_simd) {
        throw std::invalid_argument(fmt::format(
            "Input wires have different numbers of SIMD values in SubsetGate#{}", GetId()));
      }
      if (parent_[i]->GetProtocol() != protocol) {
        throw std::invalid_argument(
            fmt::format("Input wires have different protocols in SubsetGate#{}", GetId()));
      }
    }
    if ((parent_[0]->GetCircuitType() == CircuitType::kArithmetic) && (parent_.size() != 1)) {
      throw std::invalid_argument(
          fmt::format("Got {} arithmetic input wires in SubsetGate#{}, only one is allowed",
                      parent_.size(), GetId()));
    }
  }

  // Register output wires.
  const std::size_t number_of_wires{parent_.size()};
  output_wires_.reserve(number_of_wires);
  for (size_t i = 0; i < number_of_wires; ++i) {
    switch (protocol) {
      case encrypto::motion::MpcProtocol::kArithmeticConstant: {
        switch (parent_[i]->GetBitLength()) {
          case 8: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint8_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          case 16: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint16_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          case 32: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint32_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          case 64: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint64_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          default:
            throw std::invalid_argument(
                fmt::format("Trying to create a ConstantArithmeticShare with invalid bitlength: {}",
                            parent_[i]->GetBitLength()));
        }
        break;
      }
      case encrypto::motion::MpcProtocol::kArithmeticGmw: {
        switch (parent_[i]->GetBitLength()) {
          case 8: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint8_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          case 16: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint16_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          case 32: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint32_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          case 64: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint64_t>>(
                    backend_, position_ids_.size()));
            break;
          }
          default:
            throw std::invalid_argument(fmt::format(
                "Trying to create a proto::arithmetic_gmw::Share with invalid bitlength: {}",
                parent_[i]->GetBitLength()));
        }
        break;
      }
      case encrypto::motion::MpcProtocol::kBmr: {
        output_wires_.emplace_back(
            GetRegister().EmplaceWire<proto::bmr::Wire>(backend_, position_ids_.size()));
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanConstant: {
        output_wires_.emplace_back(
            GetRegister().EmplaceWire<proto::ConstantBooleanWire>(backend_, position_ids_.size()));
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanGmw: {
        output_wires_.emplace_back(
            GetRegister().EmplaceWire<proto::boolean_gmw::Wire>(backend_, position_ids_.size()));
        break;
      }
      default:
        throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in SubsetGate"));
    }
  }
}

SubsetGate::SubsetGate(const SharePointer& parent, std::span<const std::size_t> position_ids)
    : SubsetGate(parent, std::vector<std::size_t>(position_ids.begin(), position_ids.end())) {}

template <typename Allocator>
void BitVectorSubsetImplementation(const BitVector<Allocator>& in, BitVector<Allocator>& out,
                                   std::span<const std::size_t> position_ids) {
  out.Resize(position_ids.size());
  for (std::size_t i = 0; i < position_ids.size(); ++i) {
    if constexpr (kDebug) {
      if (position_ids[i] >= in.GetSize()) {
        throw std::out_of_range(
            fmt::format("Trying to access SIMD value #{} out of {} SIMD values in SubsetGate",
                        position_ids[i], in.GetSize()));
      }
    }
    out.Set(in[position_ids[i]], i);
  }
}

void SubsetGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Nothing to do in the setup phase of SubsetGate with id#{}", gate_id_));
  }
  if (parent_[0]->GetProtocol() == MpcProtocol::kBmr) {
    for (std::size_t i = 0; i < output_wires_.size(); ++i) {
      auto in = std::dynamic_pointer_cast<proto::bmr::Wire>(parent_[i]);
      assert(in);
      auto out = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_[i]);
      assert(out);
      in->GetSetupReadyCondition()->Wait();

      for (std::size_t j = 0; j < parent_.size(); ++j) {
        BitVectorSubsetImplementation(in->GetPermutationBits(), out->GetMutablePermutationBits(),
                                      position_ids_);
        out->GetMutableSecretKeys().resize(position_ids_.size());
        for (std::size_t k = 0; k < position_ids_.size(); ++k) {
          out->GetMutableSecretKeys()[k] = in->GetSecretKeys()[position_ids_[k]];
        }
      }
      out->SetSetupIsReady();
    }
  }
}

template <typename WireType>
void ArithmeticSubsetOnlineImplementation(WirePointer parent_wire, WirePointer output_wire,
                                          std::span<const std::size_t> position_ids) {
  auto in = std::dynamic_pointer_cast<WireType>(parent_wire);
  assert(in);
  auto out = std::dynamic_pointer_cast<WireType>(output_wire);
  assert(out);
  out->GetMutableValues().resize(position_ids.size());

  for (std::size_t i = 0; i < position_ids.size(); ++i) {
    if constexpr (kDebug) {
      if (position_ids[i] >= in->GetValues().size()) {
        throw std::out_of_range(
            fmt::format("Trying to access SIMD value #{} out of {} SIMD values in SubsetGate",
                        position_ids[i], in->GetValues().size()));
      }
    }
    out->GetMutableValues()[i] = in->GetValues()[position_ids[i]];
  }
}

template <typename T>
void ArithmeticGmwSubsetOnline(WirePointer parent_wire, WirePointer output_wire,
                               std::span<const std::size_t> position_ids) {
  ArithmeticSubsetOnlineImplementation<proto::arithmetic_gmw::Wire<T>>(parent_wire, output_wire,
                                                                       position_ids);
}

template <typename T>
void ArithmeticConstantSubsetOnline(WirePointer parent_wire, WirePointer output_wire,
                                    std::span<const std::size_t> position_ids) {
  ArithmeticSubsetOnlineImplementation<proto::ConstantArithmeticWire<T>>(parent_wire, output_wire,
                                                                         position_ids);
}

void SubsetGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of SubsetGate with id#{}", gate_id_));
  }
  for (auto& wire : parent_) {
    wire->GetIsReadyCondition().Wait();
  }
  const encrypto::motion::MpcProtocol protocol{parent_[0]->GetProtocol()};
  switch (protocol) {
    case encrypto::motion::MpcProtocol::kArithmeticConstant: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          ArithmeticConstantSubsetOnline<std::uint8_t>(parent_[0], output_wires_[0], position_ids_);
          break;
        }
        case 16: {
          ArithmeticConstantSubsetOnline<std::uint16_t>(parent_[0], output_wires_[0],
                                                        position_ids_);
          break;
        }
        case 32: {
          ArithmeticConstantSubsetOnline<std::uint32_t>(parent_[0], output_wires_[0],
                                                        position_ids_);
          break;
        }
        case 64: {
          ArithmeticConstantSubsetOnline<std::uint64_t>(parent_[0], output_wires_[0],
                                                        position_ids_);
          break;
        }
        default:
          throw std::invalid_argument(
              fmt::format("Trying to create a ConstantArithmeticShare with invalid bitlength: {}",
                          output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kArithmeticGmw: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          ArithmeticGmwSubsetOnline<std::uint8_t>(parent_[0], output_wires_[0], position_ids_);
          break;
        }
        case 16: {
          ArithmeticGmwSubsetOnline<std::uint16_t>(parent_[0], output_wires_[0], position_ids_);
          break;
        }
        case 32: {
          ArithmeticGmwSubsetOnline<std::uint32_t>(parent_[0], output_wires_[0], position_ids_);
          break;
        }
        case 64: {
          ArithmeticGmwSubsetOnline<std::uint64_t>(parent_[0], output_wires_[0], position_ids_);
          break;
        }
        default:
          throw std::invalid_argument(fmt::format(
              "Trying to create a proto::arithmetic_gmw::Share with invalid bitlength: {}",
              output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      const std::size_t number_of_parties{GetConfiguration().GetNumOfParties()};
      for (std::size_t i = 0; i < parent_.size(); ++i) {
        auto in = std::dynamic_pointer_cast<proto::bmr::Wire>(parent_[i]);
        assert(in);
        auto out = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_[i]);
        assert(out);
        BitVectorSubsetImplementation(in->GetPublicValues(), out->GetMutablePublicValues(),
                                      position_ids_);
        out->GetMutablePublicKeys().resize(position_ids_.size() * number_of_parties);
        for (std::size_t j = 0; j < position_ids_.size(); ++j) {
          std::copy_n(in->GetPublicKeys().begin() + position_ids_[j] * number_of_parties,
                      number_of_parties,
                      out->GetMutablePublicKeys().begin() + j * number_of_parties);
        }
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanConstant: {
      for (std::size_t i = 0; i < parent_.size(); ++i) {
        auto in = std::dynamic_pointer_cast<proto::ConstantBooleanWire>(parent_[i]);
        assert(in);
        auto out = std::dynamic_pointer_cast<proto::ConstantBooleanWire>(output_wires_[i]);
        assert(out);
        out->GetMutableValues().Resize(in->GetValues().GetSize());
        BitVectorSubsetImplementation(in->GetValues(), out->GetMutableValues(), position_ids_);
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      for (std::size_t i = 0; i < parent_.size(); ++i) {
        auto in = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(parent_[i]);
        assert(in);
        auto out = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(output_wires_[i]);
        assert(out);
        out->GetMutableValues().Resize(in->GetValues().GetSize());
        BitVectorSubsetImplementation(in->GetValues(), out->GetMutableValues(), position_ids_);
      }
      break;
    }
    default:
      throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in SubsetGate"));
  }
}

const SharePointer SubsetGate::GetOutputAsShare() {
  encrypto::motion::SharePointer result{nullptr};
  const encrypto::motion::MpcProtocol protocol{parent_[0]->GetProtocol()};
  switch (protocol) {
    case encrypto::motion::MpcProtocol::kArithmeticConstant: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint8_t>>(output_wires_);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 16: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint16_t>>(output_wires_);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 32: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint32_t>>(output_wires_);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 64: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint64_t>>(output_wires_);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        default:
          throw std::invalid_argument(
              fmt::format("Trying to create a ConstantArithmeticShare with invalid bitlength: {}",
                          output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kArithmeticGmw: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint8_t>>(output_wires_[0]);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 16: {
          auto tmp =
              std::make_shared<proto::arithmetic_gmw::Share<std::uint16_t>>(output_wires_[0]);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 32: {
          auto tmp =
              std::make_shared<proto::arithmetic_gmw::Share<std::uint32_t>>(output_wires_[0]);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 64: {
          auto tmp =
              std::make_shared<proto::arithmetic_gmw::Share<std::uint64_t>>(output_wires_[0]);
          assert(tmp);
          result = std::static_pointer_cast<Share>(tmp);
          break;
        }
        default:
          throw std::invalid_argument(fmt::format(
              "Trying to create a proto::arithmetic_gmw::Share with invalid bitlength: {}",
              output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      auto tmp = std::make_shared<proto::bmr::Share>(output_wires_);
      assert(tmp);
      result = std::static_pointer_cast<Share>(tmp);
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanConstant: {
      auto tmp = std::make_shared<proto::ConstantBooleanShare>(output_wires_);
      assert(tmp);
      result = std::static_pointer_cast<Share>(tmp);
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      auto tmp = std::make_shared<proto::boolean_gmw::Share>(output_wires_);
      assert(tmp);
      result = std::static_pointer_cast<Share>(tmp);
      break;
    }
    default:
      throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in SubsetGate"));
  }
  return std::static_pointer_cast<Share>(result);
}

}  // namespace encrypto::motion