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

#include <future>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "test_constants.h"
#include "utility/bit_vector.h"
#include "utility/condition.h"
#include "utility/helpers.h"

namespace {
TEST(Condition, WaitNotifyOne) {
  int i = 0;
  encrypto::motion::Condition condition([&i]() { return i == 1; });

  std::future<bool> wait_0 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });
  std::future<bool> wait_1 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });
  std::future<bool> wait_2 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });

  {
    std::scoped_lock<std::mutex>(condition.GetMutex());
    i = 1;
  }

  condition.NotifyOne();
  condition.NotifyOne();
  condition.NotifyOne();

  wait_0.wait();
  ASSERT_TRUE(wait_0.get());

  wait_1.wait();
  ASSERT_TRUE(wait_1.get());

  wait_2.wait();
  ASSERT_TRUE(wait_2.get());
}

TEST(Condition, WaitNotifyAll) {
  int i = 0;
  encrypto::motion::Condition condition([&i]() { return i == 1; });

  std::future<bool> wait_0 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });
  std::future<bool> wait_1 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });
  std::future<bool> wait_2 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });

  {
    std::scoped_lock<std::mutex>(condition.GetMutex());
    i = 1;
  }

  condition.NotifyAll();

  wait_0.wait();
  ASSERT_TRUE(wait_0.get());

  wait_1.wait();
  ASSERT_TRUE(wait_1.get());

  wait_2.wait();
  ASSERT_TRUE(wait_2.get());
}

TEST(Condition, WaitForTrue) {
  int i = 0;
  encrypto::motion::Condition condition([&i]() { return i == 1; });

  std::future<bool> wait_0 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });
  std::future<bool> wait_1 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });
  std::future<bool> wait_2 =
      std::async(std::launch::async, [&condition]() { return condition.Wait(); });

  {
    std::scoped_lock<std::mutex>(condition.GetMutex());
    i = 1;
  }

  condition.NotifyAll();

  wait_0.wait();
  ASSERT_TRUE(wait_0.get());

  wait_1.wait();
  ASSERT_TRUE(wait_1.get());

  wait_2.wait();
  ASSERT_TRUE(wait_2.get());
}

TEST(Condition, WaitForFalse) {
  int i = 0;
  encrypto::motion::Condition condition([&i]() { return i == 1; });

  std::future<bool> wait_0 = std::async(std::launch::async, [&condition]() {
    return condition.WaitFor(std::chrono::microseconds(1));
  });

  condition.NotifyOne();

  std::this_thread::sleep_for(std::chrono::microseconds(10));

  wait_0.wait();
  ASSERT_FALSE(wait_0.get());

  {
    std::scoped_lock<std::mutex>(condition.GetMutex());
    i = 1;
  }

  std::future<bool> wait_1 = std::async(
      std::launch::async, [&condition]() { return condition.WaitFor(std::chrono::seconds(100)); });

  std::future<bool> wait_2 = std::async(
      std::launch::async, [&condition]() { return condition.WaitFor(std::chrono::seconds(100)); });

  condition.NotifyAll();

  wait_1.wait();
  ASSERT_TRUE(wait_1.get());

  wait_2.wait();
  ASSERT_TRUE(wait_2.get());
}

TEST(Condition, WaitForComplexFunction) {
  struct {
    std::vector<int> v{0, 1, 2};
    auto GetCondition() {
      return encrypto::motion::Condition([this]() { return v.size() == 1; });
    }
  } temporary_struct;

  auto condition = temporary_struct.GetCondition();

  std::future<bool> wait_0 = std::async(std::launch::async, [&condition]() {
    return condition.WaitFor(std::chrono::microseconds(5));
  });

  {
    std::scoped_lock<std::mutex>(condition.GetMutex());
    temporary_struct.v.erase(temporary_struct.v.end() - 1);
  }

  condition.NotifyOne();

  std::this_thread::sleep_for(std::chrono::microseconds(10));

  wait_0.wait();
  ASSERT_FALSE(wait_0.get());

  std::future<bool> wait_1 = std::async(
      std::launch::async, [&condition]() { return condition.WaitFor(std::chrono::seconds(100)); });
  std::future<bool> wait_2 = std::async(
      std::launch::async, [&condition]() { return condition.WaitFor(std::chrono::seconds(100)); });

  {
    std::scoped_lock<std::mutex>(condition.GetMutex());
    temporary_struct.v.erase(temporary_struct.v.end() - 1);
  }

  condition.NotifyAll();

  wait_1.wait();
  ASSERT_TRUE(wait_1.get());

  wait_2.wait();
  ASSERT_TRUE(wait_2.get());
}

TEST(InputOutputUnVectorization, UnsignedIntegers) {
  constexpr std::uint8_t kV8 = 156;
  constexpr std::uint8_t kV8Min = std::numeric_limits<std::uint8_t>::min();
  constexpr std::uint8_t kV8Max = std::numeric_limits<std::uint8_t>::max();

  constexpr std::uint16_t kV16 = 15679;
  constexpr std::uint16_t kV16Min = std::numeric_limits<std::uint16_t>::min();
  constexpr std::uint16_t kV16Max = std::numeric_limits<std::uint16_t>::max();

  constexpr std::uint32_t kV32 = 429496729l;
  constexpr std::uint32_t kV32Min = std::numeric_limits<std::uint32_t>::min();
  constexpr std::uint32_t kV32Max = std::numeric_limits<std::uint32_t>::max();

  constexpr std::uint64_t kV64 = 171798691840ll;
  constexpr std::uint64_t kV64Min = std::numeric_limits<std::uint64_t>::min();
  constexpr std::uint64_t kV64Max = std::numeric_limits<std::uint64_t>::max();

  auto f = [](auto v, auto v_min, auto v_max) {
    static_assert(std::is_same_v<decltype(v), decltype(v_min)>);
    static_assert(std::is_same_v<decltype(v), decltype(v_max)>);
    using T = decltype(v);

    const auto v_i{encrypto::motion::ToInput(v)};
    const auto v_min_i{encrypto::motion::ToInput(v_min)};
    const auto v_max_i{encrypto::motion::ToInput(v_max)};

    const auto v_check{encrypto::motion::ToOutput<T>(v_i)};
    const auto v_min_check{encrypto::motion::ToOutput<T>(v_min_i)};
    const auto v_max_check{encrypto::motion::ToOutput<T>(v_max_i)};

    EXPECT_EQ(v, v_check);
    EXPECT_EQ(v_min, v_min_check);
    EXPECT_EQ(v_max, v_max_check);
  };

  f(kV8, kV8Min, kV8Max);
  f(kV16, kV16Min, kV16Max);
  f(kV32, kV32Min, kV32Max);
  f(kV64, kV64Min, kV64Max);
}

TEST(InputOutputUnVectorization, VectorsOfUnsignedIntegers) {
  std::vector<std::uint8_t> kV8 = {156, 0, std::numeric_limits<std::uint8_t>::max()};
  std::vector<std::uint16_t> kV16 = {15679, 0, std::numeric_limits<std::uint16_t>::max()};
  std::vector<std::uint32_t> kV32 = {429496729l, 0, std::numeric_limits<std::uint32_t>::max()};
  std::vector<std::uint64_t> kV64 = {171798691840ll, 0, std::numeric_limits<std::uint64_t>::max()};

  const auto v8_i{encrypto::motion::ToInput(kV8)};
  const auto v16_i{encrypto::motion::ToInput(kV16)};
  const auto v32_i{encrypto::motion::ToInput(kV32)};
  const auto v64_i{encrypto::motion::ToInput(kV64)};

  const auto v8_check{encrypto::motion::ToVectorOutput<std::uint8_t>(v8_i)};
  const auto v16_check{encrypto::motion::ToVectorOutput<std::uint16_t>(v16_i)};
  const auto v32_check{encrypto::motion::ToVectorOutput<std::uint32_t>(v32_i)};
  const auto v64_check{encrypto::motion::ToVectorOutput<std::uint64_t>(v64_i)};

  EXPECT_EQ(kV8, v8_check);
  EXPECT_EQ(kV16, v16_check);
  EXPECT_EQ(kV32, v32_check);
  EXPECT_EQ(kV64, v64_check);
}

template <typename T>
class TwosComplementTest : public testing::Test {
};

using TwosComplementUnsignedTypes =
    ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;
TYPED_TEST_SUITE(TwosComplementTest, TwosComplementUnsignedTypes);

TYPED_TEST(TwosComplementTest, Conversion) {
  using U = TypeParam;
  using S = typename std::make_signed_t<U>;
  constexpr std::size_t num_values{std::min(static_cast<std::size_t>(std::numeric_limits<U>::max()),
                                            static_cast<std::size_t>(10000))};

  constexpr S begin{static_cast<S>(0) - static_cast<S>(num_values / 2)};

  for (S i = begin; (i - begin) < num_values; ++i) {
    U u{encrypto::motion::ToTwosComplement(i)};
    S s{encrypto::motion::FromTwosComplement(u)};
    ASSERT_EQ(i, s);
    if (std::signbit(i)) {  // is negative
      U positive_u = -u;
      ASSERT_EQ(-i, positive_u);
    } else {  // is positive
      ASSERT_EQ(i, u);
    }
  }
}

}  // namespace