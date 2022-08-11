//
// Created by liangzhao on 09.05.22.
//

#include "secure_fixed_point_agmw_CS.h"
#include <fmt/format.h>
#include "base/backend.h"
#include "base/register.h"
#include "utility/MOTION_dp_mechanism_helper/fixed_point_operation.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureFixedPointAgmwCS::SecureFixedPointAgmwCS(const SharePointer& v, std::size_t k, std::size_t f)
    : v_(std::make_unique<ShareWrapper>(v)),
      k_(k),
      f_(f),
      logger_(v_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFixedPointAgmwCS::SecureFixedPointAgmwCS(SharePointer&& v, std::size_t k, std::size_t f)
    : v_(std::make_unique<ShareWrapper>(std::move(v))),
      k_(k),
      f_(f),
      logger_(v_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::operator+(
    const SecureFixedPointAgmwCS& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct fixed_point_other =
      other.v_->CreateFixedPointShareStruct(*other.v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxAdd_CS<T>(fixed_point_this, fixed_point_other);
  return SecureFixedPointAgmwCS(result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::operator-(
    const SecureFixedPointAgmwCS& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct fixed_point_other =
      other.v_->CreateFixedPointShareStruct(*other.v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxSub_CS<T>(fixed_point_this, fixed_point_other);
  return SecureFixedPointAgmwCS(result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::operator*(
    const SecureFixedPointAgmwCS& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct fixed_point_other =
      other.v_->CreateFixedPointShareStruct(*other.v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxMul_CS<T>(fixed_point_this, fixed_point_other);
  return SecureFixedPointAgmwCS(result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::operator/(
    const SecureFixedPointAgmwCS& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct fixed_point_other =
      other.v_->CreateFixedPointShareStruct(*other.v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxDiv_CS<T>(fixed_point_this, fixed_point_other);
  return SecureFixedPointAgmwCS(result);
}

// TODO: implementation
SecureFixedPointAgmwCS SecureFixedPointAgmwCS::DivConst(const T& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  // FixedPointStruct<T> fixed_point_other = CreateFixedPointStruct<T>(other, k_, f_);
  FixedPointShareStruct result = v_.get()->FxDivSimple_CS<T, T_int>(fixed_point_this, other);
  return SecureFixedPointAgmwCS(result);
}

ShareWrapper SecureFixedPointAgmwCS::operator<(const SecureFixedPointAgmwCS& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct fixed_point_other =
      other.v_->CreateFixedPointShareStruct(*other.v_, k_, f_);
  ShareWrapper result = v_.get()->FxLT_CS<T>(fixed_point_this, fixed_point_other);
  return result;
}

ShareWrapper SecureFixedPointAgmwCS::operator>(const SecureFixedPointAgmwCS& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct fixed_point_other =
      other.v_->CreateFixedPointShareStruct(*other.v_, k_, f_);
  ShareWrapper result = v_.get()->FxLT_CS<T>(fixed_point_other, fixed_point_this);
  return result;
}

// SecureUnsignedInteger SecureFixedPointAgmwCS::Ceil() const {
//   ShareWrapper result = v_.get()->FxFloor_CS<T>(*v_, k_, f_);
//   return SecureUnsignedInteger(result);
// }

// TODO: implement
SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Ceil() const {}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::RoundTowardsZero() const {
  ShareWrapper arithemtic_gmw_share_v_right_shift = v_->ArithmeticRightShift<T>(*v_, f_);
  ShareWrapper fixed_point_arithemtic_gmw_share_v_left_shift = v_->ArithmeticLeftShift<T>(*v_, f_);
  return fixed_point_arithemtic_gmw_share_v_left_shift;
}

ShareWrapper SecureFixedPointAgmwCS::Fx2IntWithRoundTowardsZero() const {
  ShareWrapper result = v_.get()->Fx2IntWithRoundTowardsZero_CS<T>(*v_, k_, f_);
  return (result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Neg() const {
  FixedPointShareStruct result = v_.get()->FxNeg_CS<T>(*v_, k_, f_);
  return SecureFixedPointAgmwCS(result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Abs() const {
  FixedPointShareStruct result = v_.get()->FxAbs_CS<T>(*v_, k_, f_);
  return SecureFixedPointAgmwCS(result);
  ;
}

ShareWrapper SecureFixedPointAgmwCS::LTZ() const {
  ShareWrapper result = v_.get()->FxLTZ_CS<T>(*v_, k_, f_);
  return result;
}

ShareWrapper SecureFixedPointAgmwCS::EQZ() const {
  ShareWrapper result = v_.get()->FxEQZ_CS<T>(*v_, k_, f_);
  return result;
}

ShareWrapper SecureFixedPointAgmwCS::operator==(const SecureFixedPointAgmwCS& other) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct fixed_point_other =
      other.v_->CreateFixedPointShareStruct(*other.v_, k_, f_);

  ShareWrapper result = v_.get()->FxEQ_CS<T>(fixed_point_this, fixed_point_other);
  return result;
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Sqrt() const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxSqrt<T, T_int>(fixed_point_this);
  return SecureFixedPointAgmwCS(result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Sqrt_P0132() const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxSqrt_P0132<T>(fixed_point_this);
  return SecureFixedPointAgmwCS(result);
}

// SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Round(const SecureFixedPointAgmwCS& other,
//                                                      bool mode) const {
//   ShareWrapper result = v_.get()->FxRound_CS<T>(*v_, mode, k_, f_);
//   return SecureFixedPointAgmwCS{result, k_, f_};
// }
//
SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Exp2_P1045() const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxExp2_P1045<T>(fixed_point_this);
  return SecureFixedPointAgmwCS(result);
}

//
SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Log2_P2508() const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxLog2_P2508<T>(fixed_point_this);
  return SecureFixedPointAgmwCS(result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Exp() const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxExp<T>(fixed_point_this);
  return SecureFixedPointAgmwCS(result);
}

//
SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Ln() const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);
  FixedPointShareStruct result = v_.get()->FxLn<T>(fixed_point_this);
  return SecureFixedPointAgmwCS(result);
}

// SecureUnsignedInteger SecureFixedPointAgmwCS::Fx2Int() const {}

SecureFloatingPointAgmwABZS SecureFixedPointAgmwCS::Fx2FL(std::size_t gamma, std::size_t l,
                                                          std::size_t k) const {
  FixedPointShareStruct fixed_point_this = v_->CreateFixedPointShareStruct(*v_, k_, f_);

  FloatingPointShareStruct result = v_.get()->Fx2FL<T>(fixed_point_this, gamma, f_, l, k);
  return SecureFloatingPointAgmwABZS(result);
}

SecureFixedPointAgmwCS SecureFixedPointAgmwCS::Out(std::size_t output_owner) const {
  return SecureFixedPointAgmwCS(v_->Out(output_owner), k_, f_);
}

template <typename T>
T SecureFixedPointAgmwCS::As() const {
  if (v_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw)
    return v_->As<T>();
  else if (v_->Get()->GetProtocol() == MpcProtocol::kBooleanGmw ||
           v_->Get()->GetProtocol() == MpcProtocol::kBooleanConstant ||
           v_->Get()->GetProtocol() == MpcProtocol::kBooleanMix ||
           v_->Get()->GetProtocol() == MpcProtocol::kBmr) {
    auto share_out = v_->As<std::vector<encrypto::motion::BitVector<>>>();
    if constexpr (std::is_unsigned<T>()) {
      return encrypto::motion::ToOutput<T>(share_out);
    } else {
      throw std::invalid_argument(
          fmt::format("Unsupported output type in SecureUnsignedInteger::As<{}>() for {} Protocol",
                      typeid(T).name(), v_->Get()->GetProtocol()));
    }
  } else {
    throw std::invalid_argument("Unsupported protocol for SecureUnsignedInteger::As()");
  }
}

template std::uint8_t SecureFixedPointAgmwCS::As() const;

template std::uint16_t SecureFixedPointAgmwCS::As() const;

template std::uint32_t SecureFixedPointAgmwCS::As() const;

template std::uint64_t SecureFixedPointAgmwCS::As() const;

// added by Liang Zhao
template __uint128_t SecureFixedPointAgmwCS::As() const;

template std::vector<std::uint8_t> SecureFixedPointAgmwCS::As() const;

template std::vector<std::uint16_t> SecureFixedPointAgmwCS::As() const;

template std::vector<std::uint32_t> SecureFixedPointAgmwCS::As() const;

template std::vector<std::uint64_t> SecureFixedPointAgmwCS::As() const;

// added by Liang Zhao
template std::vector<__uint128_t> SecureFixedPointAgmwCS::As() const;

template <typename T>
double SecureFixedPointAgmwCS::AsFixedPoint() const {
  if (v_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    T v = v_->template As<T>();

    double result = FixedPointToDouble<T, T_int>(v, k_, f_);

    return result;
  } else {
    throw std::invalid_argument(
        fmt::format("Unsupported output type in SecureFixedPointAgmwCS::As<{}>() for {} Protocol",
                    typeid(T).name(), v_->Get()->GetProtocol()));
  }
}

template double SecureFixedPointAgmwCS::AsFixedPoint<__uint128_t>() const;

// TODO: implement
template <typename T>
std::vector<double> SecureFixedPointAgmwCS::AsFixedPointVector() const {
  if (v_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    std::vector<T> v_vector = v_->template As<std::vector<T>>();

    std::vector<double> result_vector = FixedPointToDouble<T, T_int>(v_vector, k_, f_);

    return result_vector;
  } else {
    throw std::invalid_argument(
        fmt::format("Unsupported output type in SecureFixedPointAgmwCS::As<{}>() for {} Protocol",
                    typeid(T).name(), v_->Get()->GetProtocol()));
  }
}

template std::vector<double> SecureFixedPointAgmwCS::AsFixedPointVector<__uint128_t>() const;

}  // namespace encrypto::motion