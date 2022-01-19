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

#include "arithmetic_gmw_wire.h"

namespace encrypto::motion::proto::arithmetic_gmw {

template <typename T>
Wire<T>::Wire(Backend& backend, std::size_t number_of_simd) : Base(backend, number_of_simd) {}

template <typename T>
Wire<T>::Wire(std::vector<T>&& values, Backend& backend)
    : Base(backend, values.size()), values_(std::move(values)) {}

template <typename T>
Wire<T>::Wire(const std::vector<T>& values, Backend& backend)
    : Base(backend, values.size()), values_(values) {}

template <typename T>
Wire<T>::Wire(T t, Backend& backend) : Base(backend, 1), values_({t}) {}

template class Wire<std::uint8_t>;
template class Wire<std::uint16_t>;
template class Wire<std::uint32_t>;
template class Wire<std::uint64_t>;
template class Wire<__uint128_t>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
