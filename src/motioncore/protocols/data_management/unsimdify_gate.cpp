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

#include "unsimdify_gate.h"

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

UnsimdifyGate::UnsimdifyGate(const SharePointer& parent) : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  if constexpr (kDebug) {
    if (parent_.empty()) {
      throw std::invalid_argument(
          fmt::format("Input share in UnsimdifyGate#{} has no wires", gate_id_));
    }
  }
  const MpcProtocol protocol{parent_[0]->GetProtocol()};
  if constexpr (kDebug) {
    for (std::size_t i = 1; i < parent_.size(); ++i) {
      if (parent_[i]->GetNumberOfSimdValues() != parent_[0]->GetNumberOfSimdValues()) {
        throw std::invalid_argument(fmt::format(
            "Input wires have different numbers of SIMD values in UnsimdifyGate#{}", GetId()));
      }
      if (parent_[i]->GetProtocol() != protocol) {
        throw std::invalid_argument(
            fmt::format("Input wires have different protocols in UnsimdifyGate#{}", GetId()));
      }
    }
    if ((parent_[0]->GetCircuitType() == CircuitType::kArithmetic) && (parent_.size() != 1)) {
      throw std::invalid_argument(
          fmt::format("Got {} arithmetic input wires in UnsimdifyGate#{}, only one is allowed",
                      parent_.size(), GetId()));
    }
  }

  // Register output wires.
  const std::size_t number_of_output_wires{parent_.size() * parent_[0]->GetNumberOfSimdValues()};
  output_wires_.reserve(number_of_output_wires);
  for (size_t i = 0; i < number_of_output_wires; ++i) {
    switch (protocol) {
      case encrypto::motion::MpcProtocol::kArithmeticConstant: {
        switch (parent_[0]->GetBitLength()) {
          case 8: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint8_t>>(
                    backend_, std::size_t(1)));
            break;
          }
          case 16: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint16_t>>(
                    backend_, std::size_t(1)));
            break;
          }
          case 32: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint32_t>>(
                    backend_, std::size_t(1)));
            break;
          }
          case 64: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::ConstantArithmeticWire<std::uint64_t>>(
                    backend_, std::size_t(1)));
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
                    backend_, std::size_t(1)));
            break;
          }
          case 16: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint16_t>>(
                    backend_, std::size_t(1)));
            break;
          }
          case 32: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint32_t>>(
                    backend_, std::size_t(1)));
            break;
          }
          case 64: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::arithmetic_gmw::Wire<std::uint64_t>>(
                    backend_, std::size_t(1)));
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
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::astra::Wire<std::uint8_t>>(backend_, 1));
            break;
          }
          case 16: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::astra::Wire<std::uint16_t>>(backend_, 1));
            break;
          }
          case 32: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::astra::Wire<std::uint32_t>>(backend_, 1));
            break;
          }
          case 64: {
            output_wires_.emplace_back(
                GetRegister().EmplaceWire<proto::astra::Wire<std::uint64_t>>(backend_, 1));
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
            GetRegister().EmplaceWire<proto::bmr::Wire>(backend_, std::size_t(1)));
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanConstant: {
        output_wires_.emplace_back(
            GetRegister().EmplaceWire<proto::ConstantBooleanWire>(backend_, std::size_t(1)));
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanGmw: {
        output_wires_.emplace_back(
            GetRegister().EmplaceWire<proto::boolean_gmw::Wire>(backend_, std::size_t(1)));
        break;
      }
      default:
        throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in UnsimdifyGate"));
    }
  }
}

void UnsimdifyGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Nothing to do in the setup phase of UnsimdifyGate with id#{}", gate_id_));
  }

  if (parent_[0]->GetProtocol() == MpcProtocol::kBmr) {
    for (std::size_t i = 0; i < parent_.size(); ++i) {
      auto in = std::dynamic_pointer_cast<proto::bmr::Wire>(parent_[i]);
      assert(in);
      in->GetSetupReadyCondition()->Wait();
      for (std::size_t j = 0; j < parent_[0]->GetNumberOfSimdValues(); ++j) {
        auto out =
            std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_[j * parent_.size() + i]);
        assert(out);

        out->GetMutablePermutationBits() = in->GetPermutationBits().Subset(j, j + 1);
        out->GetMutableSecretKeys().resize(1);
        out->GetMutableSecretKeys()[0] = in->GetSecretKeys()[j];
        out->SetSetupIsReady();
      }
    }
  }
}

template <typename WireType>
void ArithmeticUnsimdifyOnlineImplementation(WirePointer parent_wire,
                                             std::span<WirePointer> output_wires) {
  auto in = std::dynamic_pointer_cast<WireType>(parent_wire);
  assert(in);
  for (std::size_t i = 0; i < output_wires.size(); ++i) {
    auto out = std::dynamic_pointer_cast<WireType>(output_wires[i]);
    assert(out);
    out->GetMutableValues().push_back(in->GetValues()[i]);
  }
}

template <typename T>
void ArithmeticGmwUnsimdifyOnline(WirePointer parent_wire, std::span<WirePointer> output_wires) {
  ArithmeticUnsimdifyOnlineImplementation<proto::arithmetic_gmw::Wire<T>>(parent_wire,
                                                                          output_wires);
}

template <typename T>
void AstraUnsimdifyOnline(WirePointer parent_wire, std::span<WirePointer> output_wires) {
  ArithmeticUnsimdifyOnlineImplementation<proto::astra::Wire<T>>(parent_wire, output_wires);
}

template <typename T>
void ArithmeticConstantUnsimdifyOnline(WirePointer parent_wire,
                                       std::span<WirePointer> output_wires) {
  ArithmeticUnsimdifyOnlineImplementation<proto::ConstantArithmeticWire<T>>(parent_wire,
                                                                            output_wires);
}

void UnsimdifyGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of UnsimdifyGate with id#{}", gate_id_));
  }
  for (auto& wire : parent_) {
    wire->GetIsReadyCondition().Wait();
  }
  const encrypto::motion::MpcProtocol protocol{parent_[0]->GetProtocol()};
  const std::size_t input_numer_of_simd{parent_[0]->GetNumberOfSimdValues()};
  switch (protocol) {
    case encrypto::motion::MpcProtocol::kArithmeticConstant: {
      switch (parent_[0]->GetBitLength()) {
        case 8: {
          ArithmeticConstantUnsimdifyOnline<std::uint8_t>(parent_[0], output_wires_);
          break;
        }
        case 16: {
          ArithmeticConstantUnsimdifyOnline<std::uint16_t>(parent_[0], output_wires_);
          break;
        }
        case 32: {
          ArithmeticConstantUnsimdifyOnline<std::uint32_t>(parent_[0], output_wires_);
          break;
        }
        case 64: {
          ArithmeticConstantUnsimdifyOnline<std::uint64_t>(parent_[0], output_wires_);
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
          ArithmeticGmwUnsimdifyOnline<std::uint8_t>(parent_[0], output_wires_);
          break;
        }
        case 16: {
          ArithmeticGmwUnsimdifyOnline<std::uint16_t>(parent_[0], output_wires_);
          break;
        }
        case 32: {
          ArithmeticGmwUnsimdifyOnline<std::uint32_t>(parent_[0], output_wires_);
          break;
        }
        case 64: {
          ArithmeticGmwUnsimdifyOnline<std::uint64_t>(parent_[0], output_wires_);
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
          AstraUnsimdifyOnline<std::uint8_t>(parent_[0], output_wires_);
          break;
        }
        case 16: {
          AstraUnsimdifyOnline<std::uint16_t>(parent_[0], output_wires_);
          break;
        }
        case 32: {
          AstraUnsimdifyOnline<std::uint32_t>(parent_[0], output_wires_);
          break;
        }
        case 64: {
          AstraUnsimdifyOnline<std::uint64_t>(parent_[0], output_wires_);
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
      for (std::size_t i = 0; i < parent_.size(); ++i) {
        auto in = std::dynamic_pointer_cast<proto::bmr::Wire>(parent_[i]);
        assert(in);
        for (std::size_t j = 0; j < input_numer_of_simd; ++j) {
          auto out =
              std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_[j * parent_.size() + i]);
          assert(out);
          out->GetMutablePublicValues() = in->GetPublicValues().Subset(j, j + 1);
          out->GetMutablePublicKeys().resize(number_of_parties);
          std::copy_n(in->GetPublicKeys().begin() + j * number_of_parties, number_of_parties,
                      out->GetMutablePublicKeys().begin());
        }
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanConstant: {
      for (std::size_t i = 0; i < parent_.size(); ++i) {
        auto in = std::dynamic_pointer_cast<proto::ConstantBooleanWire>(parent_[i]);
        assert(in);
        for (std::size_t j = 0; j < input_numer_of_simd; ++j) {
          auto out = std::dynamic_pointer_cast<proto::ConstantBooleanWire>(
              output_wires_[j * parent_.size() + i]);
          assert(out);
          out->GetMutableValues() = in->GetValues().Subset(j, j + 1);
        }
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      for (std::size_t i = 0; i < parent_.size(); ++i) {
        auto in = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(parent_[i]);
        assert(in);
        for (std::size_t j = 0; j < input_numer_of_simd; ++j) {
          auto out = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(
              output_wires_[j * parent_.size() + i]);
          assert(out);
          out->GetMutableValues() = in->GetValues().Subset(j, j + 1);
        }
      }
      break;
    }
    default:
      throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in UnsimdifyGate"));
  }
}

std::vector<SharePointer> UnsimdifyGate::GetOutputAsVectorOfShares() {
  std::vector<encrypto::motion::SharePointer> result(parent_[0]->GetNumberOfSimdValues());

  for (std::size_t i = 0; i < parent_[0]->GetNumberOfSimdValues(); ++i) {
    encrypto::motion::SharePointer share{nullptr};
    std::vector<encrypto::motion::WirePointer> output_wires(
        output_wires_.begin() + parent_.size() * i,
        output_wires_.begin() + parent_.size() * (i + 1));
    const encrypto::motion::MpcProtocol protocol{parent_[0]->GetProtocol()};
    switch (protocol) {
      case encrypto::motion::MpcProtocol::kArithmeticConstant: {
        switch (parent_[0]->GetBitLength()) {
          case 8: {
            auto tmp = std::make_shared<proto::ConstantArithmeticShare<std::uint8_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 16: {
            auto tmp =
                std::make_shared<proto::ConstantArithmeticShare<std::uint16_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 32: {
            auto tmp =
                std::make_shared<proto::ConstantArithmeticShare<std::uint32_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 64: {
            auto tmp =
                std::make_shared<proto::ConstantArithmeticShare<std::uint64_t>>(output_wires);
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
            auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint8_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 16: {
            auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint16_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 32: {
            auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint32_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 64: {
            auto tmp = std::make_shared<proto::arithmetic_gmw::Share<std::uint64_t>>(output_wires);
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
            auto tmp = std::make_shared<proto::astra::Share<std::uint8_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 16: {
            auto tmp = std::make_shared<proto::astra::Share<std::uint16_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 32: {
            auto tmp = std::make_shared<proto::astra::Share<std::uint32_t>>(output_wires);
            assert(tmp);
            share = std::static_pointer_cast<Share>(tmp);
            break;
          }
          case 64: {
            auto tmp = std::make_shared<proto::astra::Share<std::uint64_t>>(output_wires);
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
        auto tmp = std::make_shared<proto::bmr::Share>(output_wires);
        assert(tmp);
        share = std::static_pointer_cast<Share>(tmp);
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanConstant: {
        auto tmp = std::make_shared<proto::ConstantBooleanShare>(output_wires);
        assert(tmp);
        share = std::static_pointer_cast<Share>(tmp);
        break;
      }
      case encrypto::motion::MpcProtocol::kBooleanGmw: {
        auto tmp = std::make_shared<proto::boolean_gmw::Share>(output_wires);
        assert(tmp);
        share = std::static_pointer_cast<Share>(tmp);
        break;
      }
      default:
        throw std::invalid_argument(fmt::format("Unrecognized MpcProtocol in UnsimdifyGate"));
    }
    result[i] = std::static_pointer_cast<Share>(share);
  }
  return result;
}

}  // namespace encrypto::motion
