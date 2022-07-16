// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include "benchmark_primitive_operations.h"

#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/block.h"
#include "utility/config.h"

template <typename T>
encrypto::motion::ShareWrapper DummyArithmeticGmwShare(encrypto::motion::PartyPointer& party,
                                                       std::size_t bit_size,
                                                       std::size_t number_of_simd) {
  std::vector<encrypto::motion::WirePointer> wires(1);
  const std::vector<T> dummy_input(number_of_simd, 0);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  wires[0] = register_pointer->EmplaceWire<encrypto::motion::proto::arithmetic_gmw::Wire<T>>(
      dummy_input, *backend);
  wires[0]->SetOnlineFinished();

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::arithmetic_gmw::Share<T>>(wires));
}

encrypto::motion::ShareWrapper DummyBmrShare(encrypto::motion::PartyPointer& party,
                                             std::size_t number_of_wires,
                                             std::size_t number_of_simd) {
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto& w : wires) {
    auto bmr_wire{
        register_pointer->EmplaceWire<encrypto::motion::proto::bmr::Wire>(dummy_input, *backend)};
    w = bmr_wire;
    bmr_wire->GetMutablePublicKeys() = encrypto::motion::Block128Vector::MakeZero(
        backend->GetConfiguration()->GetNumOfParties() * number_of_simd);
    bmr_wire->GetMutableSecretKeys() = encrypto::motion::Block128Vector::MakeZero(number_of_simd);
    bmr_wire->GetMutablePermutationBits() = encrypto::motion::BitVector<>(number_of_simd);
    bmr_wire->SetSetupIsReady();
    bmr_wire->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::bmr::Share>(wires));
}

encrypto::motion::ShareWrapper DummyBooleanGmwShare(encrypto::motion::PartyPointer& party,
                                                    std::size_t number_of_wires,
                                                    std::size_t number_of_simd) {
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto& w : wires) {
    w = register_pointer->EmplaceWire<encrypto::motion::proto::boolean_gmw::Wire>(dummy_input,
                                                                                  *backend);
    w->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::boolean_gmw::Share>(wires));
}

encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer& party, std::size_t number_of_simd, std::size_t bit_size,
    encrypto::motion::MpcProtocol protocol,
    encrypto::motion::PrimitiveOperationType operation_type) {
  const std::vector<encrypto::motion::BitVector<>> temporary_boolean(
      bit_size, encrypto::motion::BitVector<>(number_of_simd));

  encrypto::motion::ShareWrapper a, b;

  switch (protocol) {
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      a = DummyBooleanGmwShare(party, bit_size, number_of_simd);
      b = DummyBooleanGmwShare(party, bit_size, number_of_simd);
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      a = DummyBmrShare(party, bit_size, number_of_simd);
      b = DummyBmrShare(party, bit_size, number_of_simd);
      break;
    }
    case encrypto::motion::MpcProtocol::kArithmeticGmw: {
      switch (bit_size) {
        case 8u: {
          a = DummyArithmeticGmwShare<std::uint8_t>(party, bit_size, number_of_simd);
          b = DummyArithmeticGmwShare<std::uint8_t>(party, bit_size, number_of_simd);
          break;
        }
        case 16u: {
          a = DummyArithmeticGmwShare<std::uint16_t>(party, bit_size, number_of_simd);
          b = DummyArithmeticGmwShare<std::uint16_t>(party, bit_size, number_of_simd);
          break;
        }
        case 32u: {
          a = DummyArithmeticGmwShare<std::uint32_t>(party, bit_size, number_of_simd);
          b = DummyArithmeticGmwShare<std::uint32_t>(party, bit_size, number_of_simd);
          break;
        }
        case 64u: {
          a = DummyArithmeticGmwShare<std::uint64_t>(party, bit_size, number_of_simd);
          b = DummyArithmeticGmwShare<std::uint64_t>(party, bit_size, number_of_simd);
          break;
        }
        default:
          throw std::invalid_argument("Invalid bit size");
      }
      break;
    }
    default:
      throw std::invalid_argument("Invalid MPC protocol");
  }

  switch (operation_type) {
    case encrypto::motion::PrimitiveOperationType::kXor: {
      a ^ b;
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kAnd: {
      a& b;
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kMux: {
      encrypto::motion::ShareWrapper selection{protocol ==
                                                       encrypto::motion::MpcProtocol::kBooleanGmw
                                                   ? DummyBooleanGmwShare(party, 1, number_of_simd)
                                                   : DummyBmrShare(party, 1, number_of_simd)};
      selection.Mux(a, b);
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kInv: {
      ~a;
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kOr: {
      a | b;
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kAdd: {
      a + b;
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kMul: {
      a* b;
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kSqr: {
      a* a;
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kIn: {
      if (protocol == encrypto::motion::MpcProtocol::kBooleanGmw)
        a = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(temporary_boolean, 0);
      else if (protocol == encrypto::motion::MpcProtocol::kBmr)
        a = party->In<encrypto::motion::MpcProtocol::kBmr>(temporary_boolean, 0);
      else if (protocol == encrypto::motion::MpcProtocol::kArithmeticGmw) {
        switch (bit_size) {
          case 8: {
            std::vector<std::uint8_t> temporary_arithmetic(number_of_simd);
            a = party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(temporary_arithmetic, 0);
            break;
          }
          case 16: {
            std::vector<std::uint16_t> temporary_arithmetic(number_of_simd);
            a = party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(temporary_arithmetic, 0);
            break;
          }
          case 32: {
            std::vector<std::uint32_t> temporary_arithmetic(number_of_simd);
            a = party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(temporary_arithmetic, 0);
            break;
          }
          case 64: {
            std::vector<std::uint64_t> temporary_arithmetic(number_of_simd);
            a = party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(temporary_arithmetic, 0);
            break;
          }
          default:
            throw std::invalid_argument("Unknown bit size");
        }
      } else
        throw std::invalid_argument("Unknown protocol");
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kOut: {
      a.Out();
      break;
    }
    // conversions
    case encrypto::motion::PrimitiveOperationType::kA2B: {
      a.Convert<encrypto::motion::MpcProtocol::kBooleanGmw>();
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kA2Y: {
      a.Convert<encrypto::motion::MpcProtocol::kBmr>();
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kB2A: {
      a.Convert<encrypto::motion::MpcProtocol::kArithmeticGmw>();
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kB2Y: {
      a.Convert<encrypto::motion::MpcProtocol::kBmr>();
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kY2A: {
      a.Convert<encrypto::motion::MpcProtocol::kArithmeticGmw>();
      break;
    }
    case encrypto::motion::PrimitiveOperationType::kY2B: {
      a.Convert<encrypto::motion::MpcProtocol::kBooleanGmw>();
      break;
    }
    default:
      throw std::invalid_argument("Unknown operation type");
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
