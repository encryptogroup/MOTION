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

#include "simdify_gate.h"

#include "base/configuration.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/astra/astra_share.h"
#include "protocols/astra/astra_wire.h"
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

SimdifyGate::SimdifyGate(std::span<SharePointer> parents)
    : OneGate(parents[0]->GetBackend()), number_of_input_shares_(parents.size()) {
  const std::size_t number_of_input_wires{parents[0]->GetWires().size()};

  for (std::size_t i = 0; i < parents.size(); ++i) {
    output_number_of_simd_values_ += parents[i]->GetNumberOfSimdValues();
  }

  if constexpr (kDebug) {
    for (std::size_t i = 1; i < parents.size(); ++i) {
      if (number_of_input_wires != parents[i]->GetWires().size()) {
        throw std::invalid_argument(fmt::format(
            "Input shares in SimdifyGate#{} have inconsistent number of wires", gate_id_));
      }
    }
  }

  parent_.reserve(number_of_input_wires * parents.size());
  for (auto& parent : parents) {
    parent_.insert(parent_.end(), parent->GetWires().begin(), parent->GetWires().end());
  }

  const MpcProtocol protocol{parent_[0]->GetProtocol()};
  if constexpr (kDebug) {
    for (std::size_t j = 0; j < parents.size(); ++j) {
      const std::size_t tmp_number_of_simd =
          parent_[j * number_of_input_wires]->GetNumberOfSimdValues();
      for (std::size_t i = 1; i < parents[j]->GetWires().size(); ++i) {
        if (parent_[j * number_of_input_wires + i]->GetNumberOfSimdValues() != tmp_number_of_simd) {
          throw std::invalid_argument(fmt::format(
              "Input wires have different numbers of SIMD values in SimdifyGate#{}", GetId()));
        }
        if (parent_[j * number_of_input_wires + i]->GetProtocol() != protocol) {
          throw std::invalid_argument(
              fmt::format("Input wires have different protocols in SimdifyGate#{}", GetId()));
        }
      }
    }
  }

  // Register output wires.
  const std::size_t number_of_output_wires{number_of_input_wires};
  output_wires_.reserve(number_of_output_wires);
  for (size_t i = 0; i < number_of_output_wires; ++i) {
    switch (protocol) {
      case encrypto::motion::MpcProtocol::kArithmeticConstant: {
        switch (parent_[0]->GetBitLength()) {
          case 8: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint8_t>>(
                    backend_, output_number_of_simd_values_));
            break;
          }
          case 16: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint16_t>>(
                    backend_, output_number_of_simd_values_));
            break;
          }
          case 32: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint32_t>>(
                    backend_, output_number_of_simd_values_));
            break;
          }
          case 64: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint64_t>>(
                    backend_, output_number_of_simd_values_));
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
        switch (parent_[0]->GetBitLength()) {
          case 8: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint8_t>>(
                    backend_, output_number_of_simd_values_));
            break;
          }
          case 16: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint16_t>>(
                    backend_, output_number_of_simd_values_));
            break;
          }
          case 32: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint32_t>>(
                    backend_, output_number_of_simd_values_));
            break;
          }
          case 64: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint64_t>>(
                    backend_, output_number_of_simd_values_));
            break;
          }
          default:
            throw std::invalid_argument(fmt::format(
                "Trying to create a proto::arithmetic_gmw::Share with invalid bitlength: {}",
                parent_[i]->GetBitLength()));
        }
        break;
      }
      case encrypto::motion::MpcProtocol::kAstra: {
        switch (parent_[0]->GetBitLength()) {
          case 8: {
            output_wires_.emplace_back(GetRegister().EmplaceWire<proto::astra::Wire<std::uint8_t>>(
                backend_, output_number_of_simd_values_));
            break;
          }
          case 16: {
            output_wires_.emplace_back(GetRegister().EmplaceWire<proto::astra::Wire<std::uint16_t>>(
                backend_, output_number_of_simd_values_));
            break;
          }
          case 32: {
            output_wires_.emplace_back(GetRegister().EmplaceWire<proto::astra::Wire<std::uint32_t>>(
                backend_, output_number_of_simd_values_));
            break;
          }
          case 64: {
            output_wires_.emplace_back(GetRegister().EmplaceWire<proto::astra::Wire<std::uint64_t>>(
                backend_, output_number_of_simd_values_));
            break;
          }
          default:
            throw std::invalid_argument(
                fmt::format("Trying to create a proto::astra::Share with invalid bitlength: {}",
                            parent_[i]->GetBitLength()));
        }
        break;
      }
      case encrypto::motion::MpcProtocol::kBmr: {
        output_wires_.emplace_back(
            GetRegister().EmplaceWire<proto::bmr::Wire>(backend_, output_number_of_simd_values_));
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanConstant: {
        output_wires_.emplace_back(GetRegister().EmplaceWire<proto::ConstantBooleanWire>(
            backend_, output_number_of_simd_values_));
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanGmw: {
        output_wires_.emplace_back(GetRegister().EmplaceWire<proto::boolean_gmw::Wire>(
            backend_, output_number_of_simd_values_));
        break;
      }
      default:
        throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in SimdifyGate"));
    }
  }
}

void SimdifyGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Nothing to do in the setup phase of SimdifyGate with id#{}", gate_id_));
  }

  if (parent_[0]->GetProtocol() == MpcProtocol::kBmr) {
    for (std::size_t i = 0; i < output_wires_.size(); ++i) {
      auto out = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_[i]);
      assert(out);
      out->GetMutablePermutationBits().Reserve(output_number_of_simd_values_);
      out->GetMutableSecretKeys().resize(output_number_of_simd_values_);
      std::size_t output_simd_offset{0};
      for (std::size_t j = 0; j < number_of_input_shares_; ++j) {
        auto in =
            std::dynamic_pointer_cast<proto::bmr::Wire>(parent_[j * output_wires_.size() + i]);
        assert(in);
        in->GetSetupReadyCondition()->Wait();
        // The input wires may have different numbers of SIMD values.
        const std::size_t input_number_of_simd{in->GetNumberOfSimdValues()};

        out->GetMutablePermutationBits().Append(in->GetPermutationBits());
        for (std::size_t k = 0; k < input_number_of_simd; ++k) {
          out->GetMutableSecretKeys()[output_simd_offset + k] = in->GetSecretKeys()[k];
        }
        output_simd_offset += input_number_of_simd;
      }
      out->SetSetupIsReady();
    }
  }
}

template <typename WireType>
void ArithmeticSimdifyOnlineImplementation(std::span<WirePointer> parent_wires,
                                           WirePointer output_wire) {
  std::size_t output_number_of_simd_values{0};
  for (auto& wire : parent_wires) output_number_of_simd_values += wire->GetNumberOfSimdValues();

  auto out = std::dynamic_pointer_cast<WireType>(output_wire);
  assert(out);
  out->GetMutableValues().reserve(output_number_of_simd_values);
  std::vector<typename WireType::value_type>& out_v{out->GetMutableValues()};

  for (auto& wire : parent_wires) {
    auto in = std::dynamic_pointer_cast<WireType>(wire);
    assert(in);
    out_v.insert(out_v.end(), in->GetValues().begin(), in->GetValues().end());
  }
}

template <typename T>
void ArithmeticGmwSimdifyOnline(std::span<WirePointer> parent_wires, WirePointer output_wire) {
  ArithmeticSimdifyOnlineImplementation<proto::arithmetic_gmw::Wire<T>>(parent_wires, output_wire);
}

template <typename T>
void ArithmeticConstantSimdifyOnline(std::span<WirePointer> parent_wires, WirePointer output_wire) {
  ArithmeticSimdifyOnlineImplementation<proto::ConstantArithmeticWire<T>>(parent_wires,
                                                                          output_wire);
}

template <typename T>
void AstraSimdifyOnline(std::span<WirePointer> parent_wires, WirePointer output_wire) {
  ArithmeticSimdifyOnlineImplementation<proto::astra::Wire<T>>(parent_wires, output_wire);
}

void SimdifyGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of SimdifyGate with id#{}", gate_id_));
  }
  for (auto& wire : parent_) {
    wire->GetIsReadyCondition().Wait();
  }
  const encrypto::motion::MpcProtocol protocol{parent_[0]->GetProtocol()};
  switch (protocol) {
    case encrypto::motion::MpcProtocol::kArithmeticConstant: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          ArithmeticConstantSimdifyOnline<std::uint8_t>(parent_, output_wires_[0]);
          break;
        }
        case 16: {
          ArithmeticConstantSimdifyOnline<std::uint16_t>(parent_, output_wires_[0]);
          break;
        }
        case 32: {
          ArithmeticConstantSimdifyOnline<std::uint32_t>(parent_, output_wires_[0]);
          break;
        }
        case 64: {
          ArithmeticConstantSimdifyOnline<std::uint64_t>(parent_, output_wires_[0]);
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
          ArithmeticGmwSimdifyOnline<std::uint8_t>(parent_, output_wires_[0]);
          break;
        }
        case 16: {
          ArithmeticGmwSimdifyOnline<std::uint16_t>(parent_, output_wires_[0]);
          break;
        }
        case 32: {
          ArithmeticGmwSimdifyOnline<std::uint32_t>(parent_, output_wires_[0]);
          break;
        }
        case 64: {
          ArithmeticGmwSimdifyOnline<std::uint64_t>(parent_, output_wires_[0]);
          break;
        }
        default:
          throw std::invalid_argument(fmt::format(
              "Trying to create a proto::arithmetic_gmw::Share with invalid bitlength: {}",
              output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kAstra: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          AstraSimdifyOnline<std::uint8_t>(parent_, output_wires_[0]);
          break;
        }
        case 16: {
          AstraSimdifyOnline<std::uint16_t>(parent_, output_wires_[0]);
          break;
        }
        case 32: {
          AstraSimdifyOnline<std::uint32_t>(parent_, output_wires_[0]);
          break;
        }
        case 64: {
          AstraSimdifyOnline<std::uint64_t>(parent_, output_wires_[0]);
          break;
        }
        default:
          throw std::invalid_argument(
              fmt::format("Trying to create a proto::astra::Share with invalid bitlength: {}",
                          output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      const std::size_t number_of_parties{GetConfiguration().GetNumOfParties()};
      for (std::size_t i = 0; i < output_wires_.size(); ++i) {
        auto out = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_[i]);
        assert(out);
        out->GetMutablePublicValues().Reserve(output_number_of_simd_values_);
        out->GetMutablePublicKeys().resize(number_of_parties * output_number_of_simd_values_);
        std::size_t output_simd_offset{0};
        for (std::size_t j = 0; j < number_of_input_shares_; ++j) {
          auto in =
              std::dynamic_pointer_cast<proto::bmr::Wire>(parent_[j * output_wires_.size() + i]);
          assert(in);
          out->GetMutablePublicValues().Append(in->GetPublicValues());
          std::copy_n(in->GetPublicKeys().begin(), in->GetPublicKeys().size(),
                      out->GetMutablePublicKeys().begin() + output_simd_offset * number_of_parties);
          const std::size_t input_number_of_simd{in->GetNumberOfSimdValues()};
          output_simd_offset += input_number_of_simd;
        }
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanConstant: {
      for (std::size_t i = 0; i < output_wires_.size(); ++i) {
        auto out = std::dynamic_pointer_cast<proto::ConstantBooleanWire>(output_wires_[i]);
        assert(out);
        out->GetMutableValues().Reserve(output_number_of_simd_values_);
        for (std::size_t j = 0; j < number_of_input_shares_; ++j) {
          auto in = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(
              parent_[j * output_wires_.size() + i]);
          assert(in);
          out->GetMutableValues().Append(in->GetValues());
        }
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      for (std::size_t i = 0; i < output_wires_.size(); ++i) {
        auto out = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(output_wires_[i]);
        assert(out);
        out->GetMutableValues().Reserve(output_number_of_simd_values_);
        for (std::size_t j = 0; j < number_of_input_shares_; ++j) {
          auto in = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(
              parent_[j * output_wires_.size() + i]);
          assert(in);
          out->GetMutableValues().Append(in->GetValues());
        }
      }
      break;
    }
    default:
      throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in SimdifyGate"));
  }
}

SharePointer SimdifyGate::GetOutputAsShare() {
  encrypto::motion::SharePointer share{nullptr};
  const encrypto::motion::MpcProtocol protocol{parent_[0]->GetProtocol()};
  switch (protocol) {
    case encrypto::motion::MpcProtocol::kArithmeticConstant: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint8_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 16: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint16_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 32: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint32_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 64: {
          auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint64_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
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
          auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint8_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 16: {
          auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint16_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 32: {
          auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint32_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 64: {
          auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint64_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        default:
          throw std::invalid_argument(fmt::format(
              "Trying to create a proto::arithmetic_gmw::Share with invalid bitlength: {}",
              output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kAstra: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          auto tmp = std::make_shared<proto::astra::Share<std::uint8_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 16: {
          auto tmp = std::make_shared<proto::astra::Share<std::uint16_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 32: {
          auto tmp = std::make_shared<proto::astra::Share<std::uint32_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        case 64: {
          auto tmp = std::make_shared<proto::astra::Share<std::uint64_t>>(output_wires_);
          assert(tmp);
          share = std::static_pointer_cast<Share>(tmp);
          break;
        }
        default:
          throw std::invalid_argument(
              fmt::format("Trying to create a proto::astra::Share with invalid bitlength: {}",
                          output_wires_[0]->GetBitLength()));
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      auto tmp = std::make_shared<proto::bmr::Share>(output_wires_);
      assert(tmp);
      share = std::static_pointer_cast<Share>(tmp);
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanConstant: {
      auto tmp = std::make_shared<proto::ConstantBooleanShare>(output_wires_);
      assert(tmp);
      share = std::static_pointer_cast<Share>(tmp);
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      auto tmp = std::make_shared<proto::boolean_gmw::Share>(output_wires_);
      assert(tmp);
      share = std::static_pointer_cast<Share>(tmp);
      break;
    }
    default:
      throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in SimdifyGate"));
  }
  return share;
}

}  // namespace encrypto::motion