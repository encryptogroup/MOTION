//
// Created by liangzhao on 09.05.22.
//

#include "secure_floating_point32_agmw_ABZS.h"
#include <fmt/format.h>
#include "base/backend.h"
#include "base/register.h"
#include "utility/MOTION_dp_mechanism_helper/floating_point_operation.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureFloatingPoint32AgmwABZS::SecureFloatingPoint32AgmwABZS(const SharePointer& mantissa,
                                                         const SharePointer& exponent,
                                                         const SharePointer& zero,
                                                         const SharePointer& sign, std::size_t l,
                                                         std::size_t k)
    : mantissa_(std::make_unique<ShareWrapper>(mantissa)),
      exponent_(std::make_unique<ShareWrapper>(exponent)),
      zero_(std::make_unique<ShareWrapper>(zero)),
      sign_(std::make_unique<ShareWrapper>(sign)),
      l_(l),
      k_(k),
      logger_(mantissa_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFloatingPoint32AgmwABZS::SecureFloatingPoint32AgmwABZS(SharePointer&& mantissa,
                                                         SharePointer&& exponent,
                                                         SharePointer&& zero, SharePointer&& sign,
                                                         std::size_t l, std::size_t k)
    : mantissa_(std::make_unique<ShareWrapper>(std::move(mantissa))),
      exponent_(std::make_unique<ShareWrapper>(std::move(exponent))),
      zero_(std::make_unique<ShareWrapper>(std::move(zero))),
      sign_(std::make_unique<ShareWrapper>(std::move(sign))),
      l_(l),
      k_(k),
      logger_(mantissa_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::operator+(
    const SecureFloatingPoint32AgmwABZS& other) const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLAdd_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, *other.mantissa_,
                                     *other.exponent_, *other.zero_, *other.sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::operator-(
    const SecureFloatingPoint32AgmwABZS& other) const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLSub_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, *other.mantissa_,
                                     *other.exponent_, *other.zero_, *other.sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::operator*(
    const SecureFloatingPoint32AgmwABZS& other) const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLMul_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, *other.mantissa_,
                                     *other.exponent_, *other.zero_, *other.sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::operator/(
    const SecureFloatingPoint32AgmwABZS& other) const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLDiv_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, *other.mantissa_,
                                     *other.exponent_, *other.zero_, *other.sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

ShareWrapper SecureFloatingPoint32AgmwABZS::operator<(
    const SecureFloatingPoint32AgmwABZS& other) const {
  ShareWrapper result_vector =
      mantissa_.get()->FLLT_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, *other.mantissa_,
                                    *other.exponent_, *other.zero_, *other.sign_, l_, k_);
  return result_vector;
}

ShareWrapper SecureFloatingPoint32AgmwABZS::operator>(
    const SecureFloatingPoint32AgmwABZS& other) const {
  ShareWrapper result =
      mantissa_.get()->FLLT_ABZS<T>(*other.mantissa_, *other.exponent_, *other.zero_, *other.sign_,
                                    *mantissa_, *exponent_, *zero_, *sign_, l_, k_);
  return result;
}

ShareWrapper SecureFloatingPoint32AgmwABZS::operator==(
    const SecureFloatingPoint32AgmwABZS& other) const {
  ShareWrapper result =
      mantissa_.get()->FLEQ_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, *other.mantissa_,
                                    *other.exponent_, *other.zero_, *other.sign_, l_, k_);
  return result;
}

ShareWrapper SecureFloatingPoint32AgmwABZS::IsNeg() const { return *sign_; }

ShareWrapper SecureFloatingPoint32AgmwABZS::IsZero() const { return *zero_; }

// TODO: determine the overflow limit
SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Sqrt() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLSqrt_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Ceil() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLRound_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, true, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Floor() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLRound_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, false, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

// SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Neg() const {
//   std::size_t num_of_simd = (mantissa_.get()->Get())->GetNumberOfSimdValues();

//   ShareWrapper constant_arithemtic_gmw_one =
//       mantissa_.get()->CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);

//   ShareWrapper sign_invert = constant_arithemtic_gmw_one - *sign_;

//   FloatingPointShareStruct floating_point = mantissa_.get()->CreateFloatingPointShareStruct(
//       *mantissa_, *exponent_, *zero_, sign_invert, l_, k_);
//   return SecureFloatingPoint32AgmwABZS(floating_point);
// }

template <typename FLType, typename IntType>
ShareWrapper SecureFloatingPoint32AgmwABZS::FL2Int() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FL2Int_ABZS<FLType, IntType>(*mantissa_, *exponent_, *zero_, *sign_, l_, k_);
  return result_vector[0];
}

template ShareWrapper SecureFloatingPoint32AgmwABZS::FL2Int<__uint128_t, std::uint8_t>() const;
template ShareWrapper SecureFloatingPoint32AgmwABZS::FL2Int<__uint128_t, std::uint16_t>() const;
template ShareWrapper SecureFloatingPoint32AgmwABZS::FL2Int<__uint128_t, std::uint32_t>() const;
template ShareWrapper SecureFloatingPoint32AgmwABZS::FL2Int<__uint128_t, std::uint64_t>() const;
template ShareWrapper SecureFloatingPoint32AgmwABZS::FL2Int<__uint128_t, __uint128_t>() const;

// TODO: implement
// TODO: too expensive, maybe use ceil, floor instead
SecureFixedPointAgmwCS SecureFloatingPoint32AgmwABZS::FL2Fx() const {}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Exp2() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLExp2_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Log2() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLLog2_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Exp() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLExp_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Ln() const {
  std::vector<ShareWrapper> result_vector =
      mantissa_.get()->FLLn_ABZS<T>(*mantissa_, *exponent_, *zero_, *sign_, l_, k_);
  return SecureFloatingPoint32AgmwABZS{result_vector, l_, k_};
}

SecureFloatingPoint32AgmwABZS SecureFloatingPoint32AgmwABZS::Out(std::size_t output_owner) const {
  return SecureFloatingPoint32AgmwABZS(mantissa_->Out(output_owner), exponent_->Out(output_owner),
                                     zero_->Out(output_owner), sign_->Out(output_owner), l_, k_);
}
// template <typename T>
// T SecureFloatingPoint32AgmwABZS::As() const {
//   if (share_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw)
//     return share_->As<T>();
//   else if (share_->Get()->GetProtocol() == MpcProtocol::kBooleanGmw ||
//            share_->Get()->GetProtocol() == MpcProtocol::kBooleanConstant ||
//            share_->Get()->GetProtocol() == MpcProtocol::kBooleanMix ||
//            share_->Get()->GetProtocol() == MpcProtocol::kBmr) {
//     auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
//     if constexpr (std::is_unsigned<T>()) {
//       return encrypto::motion::ToOutput<T>(share_out);
//     } else {
//       throw std::invalid_argument(
//           fmt::format("Unsupported output type in SecureUnsignedInteger::As<{}>() for {}
//           Protocol",
//                       typeid(T).name(), share_->Get()->GetProtocol()));
//     }
//   } else {
//     throw std::invalid_argument("Unsupported protocol for SecureUnsignedInteger::As()");
//   }
// }

// template std::uint8_t SecureFloatingPoint32AgmwABZS::As() const;

// template std::uint16_t SecureFloatingPoint32AgmwABZS::As() const;

// template std::uint32_t SecureFloatingPoint32AgmwABZS::As() const;

// template std::uint64_t SecureFloatingPoint32AgmwABZS::As() const;

// // added by Liang Zhao
// template __uint128_t SecureFloatingPoint32AgmwABZS::As() const;

// template std::vector<std::uint8_t> SecureFloatingPoint32AgmwABZS::As() const;

// template std::vector<std::uint16_t> SecureFloatingPoint32AgmwABZS::As() const;

// template std::vector<std::uint32_t> SecureFloatingPoint32AgmwABZS::As() const;

// template std::vector<std::uint64_t> SecureFloatingPoint32AgmwABZS::As() const;

// // added by Liang Zhao
// template std::vector<__uint128_t> SecureFloatingPoint32AgmwABZS::As() const;

template <typename T>
double SecureFloatingPoint32AgmwABZS::AsFloatingPoint() const {
  if (mantissa_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    // std::cout << "AsFloatingPoint" << std::endl;

    T mantissa = mantissa_->template As<T>();
    T exponent = exponent_->template As<T>();
    T zero = zero_->template As<T>();
    T sign = sign_->template As<T>();

    // std::cout<<"std::int64_t(mantissa): "<<std::int64_t(mantissa) << std::endl;
    // std::cout<<"std::int64_t(exponent): "<<std::int64_t(exponent) << std::endl;
    // std::cout<<"std::int64_t(zero): "<<std::int64_t(zero) << std::endl;
    // std::cout<<"std::int64_t(sign): "<<std::int64_t(sign) << std::endl;

    double result = FloatingPointToDouble<T>(mantissa, exponent, zero, sign, l_, k_);
    // double result = FloatingPointToDouble<T>(mantissa, exponent, zero, sign, 40, k_);

    return result;
  } else {

    // TODO: fix later
    // throw std::invalid_argument(fmt::format(
    //     "Unsupported output type in SecureFloatingPoint32AgmwABZS::As<{}>() for {} Protocol",
    //     typeid(T).name(), mantissa_->Get()->GetProtocol()));
  }
}

template double SecureFloatingPoint32AgmwABZS::AsFloatingPoint<__uint128_t>() const;

template <typename T>
std::vector<double> SecureFloatingPoint32AgmwABZS::AsFloatingPointVector() const {
  if (mantissa_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    std::vector<T> mantissa = mantissa_->template As<std::vector<T>>();
    std::vector<T> exponent = exponent_->template As<std::vector<T>>();
    std::vector<T> zero = zero_->template As<std::vector<T>>();
    std::vector<T> sign = sign_->template As<std::vector<T>>();

    std::vector<double> result_vector =
        FloatingPointToDouble<T>(mantissa, exponent, zero, sign, l_, k_);
    // double result = FloatingPointToDouble<T>(mantissa, exponent, zero, sign, 40, k_);

    return result_vector;
  } else {
    // throw std::invalid_argument(fmt::format(
    //     "Unsupported output type in SecureFloatingPoint32AgmwABZS::As<{}>() for {} Protocol",
    //     typeid(T).name(), mantissa_->Get()->GetProtocol()));
  }
}

template std::vector<double> SecureFloatingPoint32AgmwABZS::AsFloatingPointVector<__uint128_t>()
    const;

}  // namespace encrypto::motion