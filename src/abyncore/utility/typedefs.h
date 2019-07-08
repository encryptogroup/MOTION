#pragma once

namespace ABYN {

namespace Gates::Interfaces {};
namespace Gates::Arithmetic {};
namespace Gates::Boolean {};
namespace Gates::Yao {};
namespace Gates::Conversion {};

// fast-access aliases for Gates
namespace Arithmetic = Gates::Arithmetic;
namespace Boolean = Gates::Boolean;
namespace Conversion = Gates::Conversion;

enum MPCProtocol : uint {
  ArithmeticGMW = 0,
  BooleanGMW = 1,
  BMR = 2,
  InvalidProtocol = 3  // for checking whether the value is valid
};

enum CircuitType : uint {
  ArithmeticType = 0,
  BooleanType = 1,
  InvalidType = 2  // for checking whether the value is valid
};

enum Role : uint {
  Server = 0,
  Client = 1,
  InvalidRole = 2  // for checking whether the value is valid
};

enum GateType : uint {
  InputGate = 0,
  InteractiveGate = 1,
  NonInteractiveGate = 2,
  InvalidGate = 3
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MultiplicationTriple = std::tuple<T, T, T>;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MT = MultiplicationTriple<T>;
}  // namespace ABYN