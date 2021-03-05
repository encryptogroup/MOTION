// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#pragma once

#include <boost/hana/at_key.hpp>
#include <boost/hana/map.hpp>
#include <boost/hana/tuple.hpp>

namespace encrypto::motion {

// TypeMap is a compile-time map whose keys are types that are mapped to
// objects of possibly different types depending on the key
// e.g. TypeMap<std::vector, int, std::string> maps
// - int (as type) to an std::vector<int> instance, and
// - std::string to an std::vector<int> instance.
// Note: latest clang does not support lambdas in unevaluated environments yet.

#if __cplusplus > 201703L && !defined(__clang__)  // C++20

template <template <typename> class Value, typename... Ts>
using TypeMap = decltype([] {
  return boost::hana::unpack(boost::hana::tuple_t<Ts...>, [](auto... t) {
    return boost::hana::make_map(
        boost::hana::make_pair(decltype(t)(), Value<typename decltype(t)::type>())...);
  });
}());

#else  // C++17

namespace detail {

template <template <typename> class Value, typename... Ts>
auto MakeTypeMap() {
  return boost::hana::unpack(boost::hana::tuple_t<Ts...>, [](auto... t) {
    return boost::hana::make_map(
        boost::hana::make_pair(decltype(t)(), Value<typename decltype(t)::type>())...);
  });
}

}  // namespace detail

template <template <typename> class Value, typename... Ts>
using TypeMap = decltype(detail::MakeTypeMap<Value, Ts...>());

#endif

}  // namespace encrypto::motion
