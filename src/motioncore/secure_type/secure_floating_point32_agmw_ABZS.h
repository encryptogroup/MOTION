#pragma once

#include "protocols/share_wrapper.h"
#include "secure_type/secure_fixed_point_agmw_CS.h"
#include "secure_type/secure_unsigned_integer.h"

namespace encrypto::motion {

class Logger;

class SecureUnsignedInteger;

class SecureFixedPointAgmwCS;

class SecureFloatingPoint32AgmwABZS {
  // 64-bit floating point
  // using T = __uint128_t;

  // TODO: implement 32-bit floating point
  // 32-bit floating point
  using T = std::uint64_t;

 public:
  SecureFloatingPoint32AgmwABZS() = default;

  SecureFloatingPoint32AgmwABZS(const SecureFloatingPoint32AgmwABZS& other)
      : SecureFloatingPoint32AgmwABZS(*other.mantissa_, *other.exponent_, *other.zero_, *other.sign_,
                                    other.l_, other.k_) {}

  //
  SecureFloatingPoint32AgmwABZS(SecureFloatingPoint32AgmwABZS&& other)
      : SecureFloatingPoint32AgmwABZS(std::move(*other.mantissa_), std::move(*other.exponent_),
                                    std::move(*other.zero_), std::move(*other.sign_), other.l_,
                                    other.k_) {
    other.mantissa_->Get().reset();
    other.exponent_->Get().reset();
    other.zero_->Get().reset();
    other.sign_->Get().reset();
  }

  SecureFloatingPoint32AgmwABZS(const ShareWrapper& mantissa, const ShareWrapper& exponent,
                              const ShareWrapper& zero, const ShareWrapper& sign,
                              const std::size_t l = 24, const std::size_t k = 8)
      : SecureFloatingPoint32AgmwABZS(*mantissa, *exponent, *zero, *sign, l, k) {}

  SecureFloatingPoint32AgmwABZS(ShareWrapper&& mantissa, ShareWrapper&& exponent, ShareWrapper&& zero,
                              ShareWrapper&& sign, std::size_t l = 24, std::size_t k = 8)
      : SecureFloatingPoint32AgmwABZS(std::move(*mantissa), std::move(*exponent), std::move(*zero),
                                    std::move(*sign), l, k) {
    mantissa.Get().reset();
    exponent.Get().reset();
    zero.Get().reset();
    sign.Get().reset();
  }

  SecureFloatingPoint32AgmwABZS(const std::vector<ShareWrapper>& arithemtic_gmw_share_floating_point,
                              const std::size_t l = 24, const std::size_t k = 8)
      : SecureFloatingPoint32AgmwABZS(*arithemtic_gmw_share_floating_point[0],
                                    *arithemtic_gmw_share_floating_point[1],
                                    *arithemtic_gmw_share_floating_point[2],
                                    *arithemtic_gmw_share_floating_point[3], l, k) {}

  SecureFloatingPoint32AgmwABZS(
      const std::vector<SharePointer>& arithemtic_gmw_share_pointer_floating_point,
      const std::size_t l = 24, const std::size_t k = 8)
      : SecureFloatingPoint32AgmwABZS(arithemtic_gmw_share_pointer_floating_point[0],
                                    arithemtic_gmw_share_pointer_floating_point[1],
                                    arithemtic_gmw_share_pointer_floating_point[2],
                                    arithemtic_gmw_share_pointer_floating_point[3], l, k) {}

  SecureFloatingPoint32AgmwABZS(const SharePointer& mantissa, const SharePointer& exponent,
                              const SharePointer& zero, const SharePointer& sign,
                              std::size_t l = 24, std::size_t k = 8);

  SecureFloatingPoint32AgmwABZS(SharePointer&& mantissa, SharePointer&& exponent, SharePointer&& zero,
                              SharePointer&& sign, std::size_t l = 24, std::size_t k = 8);

  SecureFloatingPoint32AgmwABZS(const FloatingPointShareStruct& floating_point_struct)
      : SecureFloatingPoint32AgmwABZS(*(floating_point_struct.mantissa),
                                    *(floating_point_struct.exponent),
                                    *(floating_point_struct.zero), *(floating_point_struct.sign),
                                    floating_point_struct.l, floating_point_struct.k) {}

  SecureFloatingPoint32AgmwABZS(FloatingPointShareStruct&& floating_point_struct)
      : SecureFloatingPoint32AgmwABZS(std::move(*(floating_point_struct.mantissa)),
                                    std::move(*(floating_point_struct.exponent)),
                                    std::move(*(floating_point_struct.zero)),
                                    std::move(*(floating_point_struct.sign)),
                                    floating_point_struct.l, floating_point_struct.k) {}

  SecureFloatingPoint32AgmwABZS& operator=(const SecureFloatingPoint32AgmwABZS& other) {
    this->mantissa_ = other.mantissa_;
    this->exponent_ = other.exponent_;
    this->zero_ = other.zero_;
    this->sign_ = other.sign_;
    this->l_ = other.l_;
    this->k_ = other.k_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureFloatingPoint32AgmwABZS& operator=(SecureFloatingPoint32AgmwABZS&& other) {
    this->mantissa_ = std::move(other.mantissa_);
    this->exponent_ = std::move(other.exponent_);
    this->zero_ = std::move(other.zero_);
    this->sign_ = std::move(other.sign_);
    this->l_ = other.l_;
    this->k_ = other.k_;
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& GetMantissa() { return *mantissa_; }

  ShareWrapper& GetExponent() { return *exponent_; }

  ShareWrapper& GetZero() { return *zero_; }

  ShareWrapper& GetSign() { return *sign_; }

  // ShareWrapper& GetError() { return *error_; }

  const ShareWrapper& GetMantissa() const { return *mantissa_; }

  const ShareWrapper& GetExponent() const { return *exponent_; }

  const ShareWrapper& GetZero() const { return *zero_; }

  const ShareWrapper& GetSign() const { return *sign_; }

  // const ShareWrapper& GetError() const { return *error_; }

  SecureFloatingPoint32AgmwABZS operator+(const SecureFloatingPoint32AgmwABZS& other) const;

  SecureFloatingPoint32AgmwABZS& operator+=(const SecureFloatingPoint32AgmwABZS& other) {
    *this = *this + other;
    return *this;
  }

  SecureFloatingPoint32AgmwABZS operator-(const SecureFloatingPoint32AgmwABZS& other) const;

  SecureFloatingPoint32AgmwABZS& operator-=(const SecureFloatingPoint32AgmwABZS& other) {
    *this = *this - other;
    return *this;
  }

  SecureFloatingPoint32AgmwABZS operator*(const SecureFloatingPoint32AgmwABZS& other) const;

  SecureFloatingPoint32AgmwABZS& operator*=(const SecureFloatingPoint32AgmwABZS& other) {
    *this = *this * other;
    return *this;
  }

  SecureFloatingPoint32AgmwABZS operator/(const SecureFloatingPoint32AgmwABZS& other) const;

  SecureFloatingPoint32AgmwABZS& operator/=(const SecureFloatingPoint32AgmwABZS& other) {
    *this = *this / other;
    return *this;
  }

  ShareWrapper operator<(const SecureFloatingPoint32AgmwABZS& other) const;

  ShareWrapper operator>(const SecureFloatingPoint32AgmwABZS& other) const;

  ShareWrapper operator==(const SecureFloatingPoint32AgmwABZS& other) const;

  ShareWrapper IsNeg() const;

  ShareWrapper IsZero() const;

  SecureFloatingPoint32AgmwABZS Sqrt() const;

  SecureFloatingPoint32AgmwABZS Ceil() const;

  SecureFloatingPoint32AgmwABZS Floor() const;

  SecureFloatingPoint32AgmwABZS Neg() const;

  // Note: Exp2, Log2 too expensive
  SecureFloatingPoint32AgmwABZS Exp2() const;
  SecureFloatingPoint32AgmwABZS Log2() const;

  SecureFloatingPoint32AgmwABZS Ln() const;

  SecureFloatingPoint32AgmwABZS Exp() const;

  template <typename FLType, typename IntType>
  ShareWrapper FL2Int() const;

  // TODO: implement
  SecureFixedPointAgmwCS FL2Fx() const;

  /// \brief converts the information on the wires to T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T>
  T As() const;

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  /// Uses ShareWrapper::Out.
  SecureFloatingPoint32AgmwABZS Out(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief converts the information on the wires to T type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T = __uint128_t>
  double AsFloatingPoint() const;

  /// \brief converts the information on the wires to T type Unsigned Integer vector.
  /// See the description in ShareWrapper::As for reference.
  template <typename T = __uint128_t>
  std::vector<double> AsFloatingPointVector() const;

 private:
  std::shared_ptr<ShareWrapper> mantissa_{nullptr};
  std::shared_ptr<ShareWrapper> exponent_{nullptr};
  std::shared_ptr<ShareWrapper> zero_{nullptr};
  std::shared_ptr<ShareWrapper> sign_{nullptr};
  // std::shared_ptr<ShareWrapper> error_{nullptr};
  std::size_t l_;
  std::size_t k_;

  std::shared_ptr<Logger> logger_{nullptr};
  std::size_t num_of_simd_;
};

}  // namespace encrypto::motion