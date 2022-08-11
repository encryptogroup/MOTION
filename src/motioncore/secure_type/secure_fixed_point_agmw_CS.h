#pragma once

#include "protocols/share_wrapper.h"
#include "secure_type/secure_floating_point_agmw_ABZS.h"
#include "secure_type/secure_unsigned_integer.h"

namespace encrypto::motion {

class Logger;

class SecureUnsignedInteger;
class SecureFloatingPointAgmwABZS;

// TODO: test use different truncation protocols

//    template <typename T = __uint128_t, typename T_int = __int128_t>
class SecureFixedPointAgmwCS {
  using T = __uint128_t;
  using T_int = __int128_t;

 public:
  SecureFixedPointAgmwCS() = default;

  SecureFixedPointAgmwCS(const SecureFixedPointAgmwCS& other)
      : SecureFixedPointAgmwCS(*other.v_, other.k_, other.f_) {}

  //
  SecureFixedPointAgmwCS(SecureFixedPointAgmwCS&& other)
      : SecureFixedPointAgmwCS(std::move(*other.v_), other.k_, other.f_) {
    other.v_->Get().reset();
  }

  SecureFixedPointAgmwCS(const ShareWrapper& v, const std::size_t k = 41, const std::size_t f = 20)
      : SecureFixedPointAgmwCS(*v, k, f) {}

  SecureFixedPointAgmwCS(ShareWrapper&& v, std::size_t k = 41, std::size_t f = 20)
      : SecureFixedPointAgmwCS(std::move(*v), k, f) {
    v.Get().reset();
  }

  SecureFixedPointAgmwCS(const SharePointer& v, std::size_t k = 41, std::size_t f = 20);

  SecureFixedPointAgmwCS(SharePointer&& v, std::size_t k = 41, std::size_t f = 20);

  SecureFixedPointAgmwCS(const FixedPointShareStruct& fixed_point_struct)
      : SecureFixedPointAgmwCS(*(fixed_point_struct.v), fixed_point_struct.k,
                               fixed_point_struct.f) {}

  SecureFixedPointAgmwCS(FixedPointShareStruct&& fixed_point_struct)
      : SecureFixedPointAgmwCS(std::move(*(fixed_point_struct.v)), fixed_point_struct.k,
                               fixed_point_struct.f) {}

  SecureFixedPointAgmwCS& operator=(const SecureFixedPointAgmwCS& other) {
    this->v_ = other.v_;
    this->k_ = other.k_;
    this->f_ = other.f_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureFixedPointAgmwCS& operator=(SecureFixedPointAgmwCS&& other) {
    this->v_ = std::move(other.v_);
    this->k_ = other.k_;
    this->f_ = other.f_;
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& GetSignedIntegerV() { return *v_; }

  //  ShareWrapper& GetError() { return *error_; }

  const ShareWrapper& GetSignedIntegerV() const { return *v_; }

  //  const ShareWrapper& GetError() const { return *error_; }

  SecureFixedPointAgmwCS operator+(const SecureFixedPointAgmwCS& other) const;

  SecureFixedPointAgmwCS& operator+=(const SecureFixedPointAgmwCS& other) {
    *this = *this + other;
    return *this;
  }

  SecureFixedPointAgmwCS operator-(const SecureFixedPointAgmwCS& other) const;

  SecureFixedPointAgmwCS& operator-=(const SecureFixedPointAgmwCS& other) {
    *this = *this - other;
    return *this;
  }

  SecureFixedPointAgmwCS operator*(const SecureFixedPointAgmwCS& other) const;

  SecureFixedPointAgmwCS& operator*=(const SecureFixedPointAgmwCS& other) {
    *this = *this * other;
    return *this;
  }

  // ! for a/b, abs(b) should be much less than 2^(k-1) and much greater than 2^(1)
  // otherwise, the result is not accurate, because we cannot represent 1/b precisely as a
  // fixed-point number
  SecureFixedPointAgmwCS operator/(const SecureFixedPointAgmwCS& other) const;

  SecureFixedPointAgmwCS& operator/=(const SecureFixedPointAgmwCS& other) {
    *this = *this / other;
    return *this;
  }

  // return division result (approximation) by a constant,
  // ! the reciprocal of T must be representative (with enough bits) in fixed-point
  // otherwise, result is inaccurate because of accuracy loss
  SecureFixedPointAgmwCS DivConst(const T& other) const;

  ShareWrapper operator<(const SecureFixedPointAgmwCS& other) const;

  ShareWrapper operator>(const SecureFixedPointAgmwCS& other) const;

  // TODO: implement
  SecureFixedPointAgmwCS Ceil() const;

  SecureFixedPointAgmwCS RoundTowardsZero() const;

  ShareWrapper Fx2IntWithRoundTowardsZero() const;

  SecureFixedPointAgmwCS Neg() const;

  SecureFixedPointAgmwCS Abs() const;

  ShareWrapper LTZ() const;

  ShareWrapper EQZ() const;

  ShareWrapper operator==(const SecureFixedPointAgmwCS& other) const;

  // ! very inaccurate for large input
  // may contain error, need improvement
  SecureFixedPointAgmwCS Sqrt() const;

  // ! accurate for input in range [0.5, 1.0]
  SecureFixedPointAgmwCS Sqrt_P0132() const;

  // ! accurate for input in range [0.0, 1.0]
  SecureFixedPointAgmwCS Exp2_P1045() const;

  // ! accurate for input in range [0.5, 1.0]
  SecureFixedPointAgmwCS Log2_P2508() const;

  // based on Exp2_P1045
  SecureFixedPointAgmwCS Exp() const;

  // based on Log2_P2508
  SecureFixedPointAgmwCS Ln() const;

  // use Ceil or Floor instead
  //   SecureUnsignedInteger Fx2Int() const;

  SecureFloatingPointAgmwABZS Fx2FL(std::size_t gamma, std::size_t l, std::size_t k) const;

  /// \brief converts the information on the wires to T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T>
  T As() const;

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  /// Uses ShareWrapper::Out.
  SecureFixedPointAgmwCS Out(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief converts the information on the wires to T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T = __uint128_t>
  double AsFixedPoint() const;

  // TODO: implement
  template <typename T = __uint128_t>
  std::vector<double> AsFixedPointVector() const;

 public:
  std::size_t k_;
  std::size_t f_;

 private:
  std::shared_ptr<ShareWrapper> v_{nullptr};
  //  std::shared_ptr<ShareWrapper> error_{nullptr};

  std::shared_ptr<Logger> logger_{nullptr};

  // FixedPointShareStruct fixed_point;
};

}  // namespace encrypto::motion