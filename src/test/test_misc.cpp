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

namespace {
TEST(Condition, Wait_NotifyOne) {
  int i = 0;
  ENCRYPTO::Condition condition([&i]() { return i == 1; });

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

TEST(Condition, Wait_NotifyAll) {
  int i = 0;
  ENCRYPTO::Condition condition([&i]() { return i == 1; });

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
  ENCRYPTO::Condition condition([&i]() { return i == 1; });

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
  ENCRYPTO::Condition condition([&i]() { return i == 1; });

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
      return ENCRYPTO::Condition([this]() { return v.size() == 1; });
    }
  } tmp_struct;

  auto condition = tmp_struct.GetCondition();

  std::future<bool> wait_0 = std::async(std::launch::async, [&condition]() {
    return condition.WaitFor(std::chrono::microseconds(5));
  });

  {
    std::scoped_lock<std::mutex>(condition.GetMutex());
    tmp_struct.v.erase(tmp_struct.v.end() - 1);
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
    tmp_struct.v.erase(tmp_struct.v.end() - 1);
  }

  condition.NotifyAll();

  wait_1.wait();
  ASSERT_TRUE(wait_1.get());

  wait_2.wait();
  ASSERT_TRUE(wait_2.get());
}

TEST(InputOutput_Un_Vectorization, UnsignedIntegers) {
  std::uint8_t v8 = 156, v8_min = 0, v8_max = std::numeric_limits<std::uint8_t>::max();
  std::uint16_t v16 = 15679, v16_min = 0, v16_max = std::numeric_limits<std::uint16_t>::max();
  std::uint32_t v32 = 429496729l, v32_min = 0, v32_max = std::numeric_limits<std::uint32_t>::max();
  std::uint64_t v64 = 171798691840ll, v64_min = 0,
                v64_max = std::numeric_limits<std::uint64_t>::max();

  auto f = [](auto v, auto v_min, auto v_max) {
    static_assert(std::is_same_v<decltype(v), decltype(v_min)>);
    static_assert(std::is_same_v<decltype(v), decltype(v_max)>);
    using T = decltype(v);

    const auto v_i{ENCRYPTO::ToInput(v)};
    const auto v_min_i{ENCRYPTO::ToInput(v_min)};
    const auto v_max_i{ENCRYPTO::ToInput(v_max)};

    const auto v_check{ENCRYPTO::ToOutput<T>(v_i)};
    const auto v_min_check{ENCRYPTO::ToOutput<T>(v_min_i)};
    const auto v_max_check{ENCRYPTO::ToOutput<T>(v_max_i)};

    EXPECT_EQ(v, v_check);
    EXPECT_EQ(v_min, v_min_check);
    EXPECT_EQ(v_max, v_max_check);
  };

  f(v8, v8_min, v8_max);
  f(v16, v16_min, v16_max);
  f(v32, v32_min, v32_max);
  f(v64, v64_min, v64_max);
}

TEST(InputOutput_Un_Vectorization, VectorsOfUnsignedIntegers) {
  std::vector<std::uint8_t> v8 = {156, 0, std::numeric_limits<std::uint8_t>::max()};
  std::vector<std::uint16_t> v16 = {15679, 0, std::numeric_limits<std::uint16_t>::max()};
  std::vector<std::uint32_t> v32 = {429496729l, 0, std::numeric_limits<std::uint32_t>::max()};
  std::vector<std::uint64_t> v64 = {171798691840ll, 0, std::numeric_limits<std::uint64_t>::max()};

  const auto v8_i{ENCRYPTO::ToInput(v8)};
  const auto v16_i{ENCRYPTO::ToInput(v16)};
  const auto v32_i{ENCRYPTO::ToInput(v32)};
  const auto v64_i{ENCRYPTO::ToInput(v64)};

  const auto v8_check{ENCRYPTO::ToVectorOutput<std::uint8_t>(v8_i)};
  const auto v16_check{ENCRYPTO::ToVectorOutput<std::uint16_t>(v16_i)};
  const auto v32_check{ENCRYPTO::ToVectorOutput<std::uint32_t>(v32_i)};
  const auto v64_check{ENCRYPTO::ToVectorOutput<std::uint64_t>(v64_i)};

  EXPECT_EQ(v8, v8_check);
  EXPECT_EQ(v16, v16_check);
  EXPECT_EQ(v32, v32_check);
  EXPECT_EQ(v64, v64_check);
}
}