// MIT License
//
// Copyright (c) 2022 Oliver Schick
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

#include "astra_wire.h"

namespace encrypto::motion::proto::astra {

template<typename T>
Wire<T>::Wire(Backend& backend, const T& value, const T& lambda_x_0, const T& lambda_x_1)
  : Base(backend, 1), value_{value}, lambda_x_i_{lambda_x_0, lambda_x_1} {}
  

template class Wire<std::uint8_t>;
template class Wire<std::uint16_t>;
template class Wire<std::uint32_t>;
template class Wire<std::uint64_t>;
template class Wire<__uint128_t>;
    
} // namespace encrypto::motion::proto::astra