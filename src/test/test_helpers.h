// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>

template <typename T>
inline T Rand() {
  unsigned char buf[sizeof(T)];
  RAND_bytes(buf, sizeof(T));
  return *reinterpret_cast<T*>(buf);
}

template <typename T>
inline std::vector<T> RandomVector(std::size_t size) {
  std::vector<T> v(size);
  std::generate(v.begin(), v.end(), Rand<T>);
  return v;
}

inline std::vector<bool> RandomBoolVector(std::size_t size) {
  std::vector<bool> bool_vector;
  bool_vector.reserve(size);

  using T = std::uint64_t;
  std::vector<T> random_T_vector = ::RandomVector<T>(ceil(double(size) / (sizeof(T) * 8)));

  for (std::size_t i = 0; i < ceil(double(size) / (sizeof(T) * 8)); i++) {
    for (std::size_t j = 0; j < (sizeof(T) * 8); j++) {
      bool_vector.emplace_back((random_T_vector[i] >> j) & 1);
    }
  }

  bool_vector.resize(size);
  return bool_vector;
}

template <typename T>
std::vector<T> RandomRangeIntegerVector(double min, double max, std::size_t n) {
  std::vector<T> random_numbers;
  random_numbers.reserve(n);
  // srand(time(NULL));
  for (std::size_t i = 0; i < n; i++) {
    // rand() will produce a random integer between 0 ... RAND_MAX where RAND_MAX
    // is a very large number... by dividing this number by RAND_MAX we will get
    // a number in the range 0 ... 1.  We typecast rand() to a double to ensure
    // that double division takes place as opposed to interger division which
    // would result in 0 OR 1 exactly.
    double random = ((double)rand()) / RAND_MAX;

    // Take the number between 0-1 above and multiply it by (max - min) to get a
    // number in the range of 0 ... (max - min)
    double range = (max - min) * random;

    // take this number in the range of 0 - (max-min) above and add min to it to
    // get a number in the range of min ... max (adding min to 0 give us min,
    // adding min to max-min gives us back max!)
    T number = min + range;
    random_numbers.emplace_back(number);
  }

  return random_numbers;
}

