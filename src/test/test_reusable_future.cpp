// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include "gtest/gtest.h"

#include "utility/reusable_future.h"

namespace {

using namespace ENCRYPTO;

TEST(ReusableFuture, SetAfterGetFuture) {
  ReusablePromise<int> promise;
  auto future = promise.get_future();
  int input_value = 42;
  promise.set_value(input_value);
  auto output_value = future.get();

  EXPECT_EQ(input_value, output_value);
}

TEST(ReusableFuture, SetBeforeGetFuture) {
  ReusablePromise<int> promise;
  int input_value = 42;
  promise.set_value(input_value);
  auto future = promise.get_future();
  auto output_value = future.get();
  EXPECT_EQ(input_value, output_value);
}

TEST(ReusableFuture, SetTwice) {
  ReusablePromise<int> promise;
  promise.set_value(42);
  EXPECT_THROW(promise.set_value(47), std::future_error);
}

TEST(ReusableFuture, SetTwiceWithReset) {
  ReusablePromise<int> promise;
  auto future = promise.get_future();

  int input_value_1 = 42;
  int input_value_2 = 47;

  promise.set_value(input_value_1);
  auto output_value_1 = future.get();
  EXPECT_EQ(input_value_1, output_value_1);

  promise.set_value(input_value_2);
  auto output_value_2 = future.get();
  EXPECT_EQ(input_value_2, output_value_2);
}

TEST(ReusableFuture, InvalidFuture) {
  ReusableFuture<int> fut;
  EXPECT_FALSE(fut.valid());
  EXPECT_THROW(fut.get(), std::future_error);
}

TEST(ReusableFuture, InvalidPromise) {
  ReusablePromise<int> promise_1;
  auto _ = std::move(promise_1);
  EXPECT_THROW(promise_1.get_future(), std::future_error);
  int i = 47;
  EXPECT_THROW(promise_1.set_value(i), std::future_error);
  EXPECT_THROW(promise_1.set_value(std::move(i)), std::future_error);
}

TEST(ReusableFuture, RetrieveFutureTwice) {
  ReusablePromise<int> promise;
  auto _ = promise.get_future();
  EXPECT_THROW(promise.get_future(), std::future_error);
}

}  // namespace
