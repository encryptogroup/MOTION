# ABY-N [![Build Status](https://travis-ci.com/Oleksandr-Tkachenko/ABYN.svg?token=vWcBQYzxXnAWavBdMFeK&branch=master)](https://travis-ci.com/Oleksandr-Tkachenko/ABYN)

### A Framework for Efficient Mixed-Protocol Secure Multi-Party Computation and Trustworthy Outsourcing

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

### Requirements

---

* A **Linux distribution** of your choice (ABY-N was developed and tested with recent versions of [Ubuntu](http://www.ubuntu.com/), [Manjaro](https://manjaro.org/) and [Arch Linux](https://www.archlinux.org/)).
* **Required packages for ABY-N:**
  * `g++` (version >=8)
    or another compiler and standard library implementing C++17 including the filesystem library
  * `make`
  * `cmake`
  * [`boost`](https://www.boost.org/) (version >=1.66)
  * **TODO** complete this list


#### Building ABY-N

##### Short Version

1. Clone the ABY-N git repository by running:
    ```
    git clone https://github.com/encryptogroup/ABY.git
    ```

2. Enter the Framework directory: `cd ABYN/`

3. Create and enter the build directory: `mkdir build && cd build`

4. Use CMake configure the build:
    ```
    cmake ..
    ```
    This also initializes and updates the Git submodules of the dependencies
    located in `extern/`.

5. Call `make` in the build directory.
   You can find the build executables and libraries in the directories `bin/`
   and `lib/`, respectively.

##### Detailed Guide

###### External Dependencies

ABY-N depends on the following libraries:
* [boost](https://www.boost.org/)
* [flatbuffers](https://github.com/google/flatbuffers)
* [fmt](https://github.com/fmtlib/fmt)
* [googletest](https://github.com/google/googletest) (optional)

These are referenced using the Git submodules in the `extern/`
directory.
During configure phase of the build (calling `cmake ..`) CMake searches your
system for these libraries. (**TODO**: is this still the case?)

* If they are already installed at a standard location, e.g., at `/usr` or
  `/usr/local`, CMake should find these automatically.
* In case they are installed at a nonstandard location, e.g., at `~/some/path/`,
  you can point CMake to their location via the
  [`CMAKE_PREFIX_PATH`](https://cmake.org/cmake/help/latest/variable/CMAKE_PREFIX_PATH.html)
  option:
    ```
    cmake .. -DCMAKE_PREFIX_PATH=~/some/path/
    ```
* Otherwise, CMake updates and initializes the Git submodules in `extern/` (if
  not already done), and the missing dependencies are built together with ABY-N.
  If you want to do this without a network connection, consider to clone the
  repository recursively.

###### Test Executables and Example Applications

ABY-N executables and test cases are not built by default.
This can be enabled with the `ABYN_BUILD_EXE` or `ABYN_BUILD_TESTS` option, respectively, e.g.:
```
cmake .. -DABYN_BUILD_EXE=On
```

###### Build Options

You can choose the build type, e.g. `Release` or `Debug` using
[`CMAKE_BUILD_TYPE`](https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html):
```
cmake .. -DCMAKE_BUILD_TYPE=Release
# or
cmake .. -DCMAKE_BUILD_TYPE=Debug
```
`Release` is selected as default and will enable optimizations, whereas `Debug` includes debug symbols.

To choose a different compiler, use the `CXX` environment variable:
```
CXX=/usr/bin/clang++ cmake ..
```

###### Cleaning the Build Directory

Executing `make clean` in the build directory removes all build artifacts.
This includes built dependencies and examples.
To clean only parts of the build, either invoke `make clean` in the specific
subdirectory or use `make -C`:

* `make clean` - clean everything
* `make -C src/abycore clean` - clean only the ABY-N library
* `make -C src/examples clean` - clean only the examples
* `make -C src/test clean` - clean only the test application
* `make -C extern clean` - clean only the built dependencies


###### Installation

In case you plan to use ABY-N for your own application, you might want to install
the ABY-N library to some place, for example system-wide (e.g. at `/usr/local`)
or somewhere in your workspace (e.g. `/path/to/aby`).
There are two relevant options:

* [`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html)
  defaults to `/usr/local` and is preprended by CMake to all installation paths
  (e.g. `lib/` and `include/` for library and header files, respectively,
  become `/usr/local/lib` and `usr/local/include`).
  CMake will also look for dependencies at this location.
* [`DESTDIR`](https://cmake.org/cmake/help/latest/envvar/DESTDIR.html)
  is used by the Makefile to install to a nonstandard location.

Example:
If you want to install ABY-N to `~/path/to/aby/prefix/{include,lib}` you can use:
```
cmake .. -DCMAKE_INSTALL_PREFIX=""
make
make DESTDIR=~/path/to/aby/prefix install
```
or
```
cmake .. -DCMAKE_INSTALL_PREFIX=~/path/to/aby/prefix
make
make install
```


#### Developer Guide and Documentation
**TODO:** We provide an extensive developer guide with many examples and explanations of how to use ABY-N.

**TODO:** Also, see the online doxygen documentation of ABY-N for further information and comments on the code.


### ABY-N Applications

---


#### Running Applications
  **TODO**
