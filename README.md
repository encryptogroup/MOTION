# MOTION - A Framework for Mixed-Protocol Multi-Party Computation [![Build Status](https://travis-ci.org/encryptogroup/MOTION.svg?branch=master)](https://travis-ci.org/encryptogroup/MOTION)

Check out our [paper](https://ia.cr/2020/1137) (published at ACM TOPS'22) for details.

This code is provided as an experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

### Requirements

---

* A **Linux distribution** of your choice (MOTION was developed and tested with recent versions of [Ubuntu](http://www.ubuntu.com/), [Manjaro](https://manjaro.org/) and [Arch Linux](https://www.archlinux.org/)).
* **Required packages for MOTION:**
  * `g++` (version >=10)
    or another compiler and standard library implementing C++20 including the filesystem library
  * `make`
  * `cmake`
  * [`boost`](https://www.boost.org/) (version >=1.75.0)
  * `OpenMP`
  * [`OpenSSL`](https://www.openssl.org/) (version >=1.1.0)
* For Windows, set these paths in PATH System Variable:
  * `path\to\cmake\bin`
  * `path\to\MinGW\bin`
  * OpenSSL can be configured by setting these variables: `OPENSSL_ROOT_DIR`, `OPENSSL_INCLUDE_DIR`
    , `OPENSSL_LIBRARIES`, `OPENSSL_CRYPTO_LIBRARY`, and `OPENSSL_SSL_LIBRARY` or pass them via `-DOPENSSL_ROOT_DIR`
    etc. in `cmake ..`


#### Building MOTION

##### Short Version

1. Clone the MOTION git repository by running:
    ```
    git clone https://github.com/encryptogroup/MOTION.git
    ```

2. Enter the Framework directory: `cd MOTION/`

3. Create and enter the build directory: `mkdir build && cd build`

4. Use CMake configure the build:
    ```
    cmake ..
    ```
   For Windows:
    ```
    cmake -G "MinGW Makefiles" ..
    ```
    This also initializes and updates the Git submodules of the dependencies
    located in `extern/`.

5. Call `make` in the build directory.
   Optionally, add `-j $number_of_parallel_jobs` to `make` for faster compilation.
   You can find the build executables and libraries in the directories `bin/`
   and `lib/`, respectively.

##### Detailed Guide

###### External Dependencies

MOTION depends on the following libraries:
* [boost](https://www.boost.org/)
* [flatbuffers](https://github.com/google/flatbuffers)
* [fmt](https://github.com/fmtlib/fmt)
* [googletest](https://github.com/google/googletest) (optional)

These are referenced using the Git submodules in the `extern/`
directory.
During configure phase of the build (calling `cmake ..`) CMake searches your
system for these libraries.

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
  not already done), and the missing dependencies are built together with MOTION.
  If you want to do this without a network connection, consider to clone the
  repository recursively.

###### Test Executables and Example Applications

MOTION executables and test cases are not built by default.
This can be enabled with the `MOTION_BUILD_EXE` or `MOTION_BUILD_TESTS` option, respectively, e.g.:
```
cmake .. -DMOTION_BUILD_EXE=On
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
* `make -C src/motioncore clean` - clean only the MOTION library
* `make -C src/examples clean` - clean only the examples
* `make -C src/test clean` - clean only the test application
* `make -C extern clean` - clean only the built dependencies


###### Installation

In case you plan to use MOTION for your own application, you might want to install
the MOTION library to some place, for example system-wide (e.g. at `/usr/local`)
or somewhere in your workspace (e.g. `/path/to/motion`).
There are two relevant options:

* [`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html)
  defaults to `/usr/local` and is preprended by CMake to all installation paths
  (e.g. `lib/` and `include/` for library and header files, respectively,
  become `/usr/local/lib` and `usr/local/include`).
  CMake will also look for dependencies at this location.
* [`DESTDIR`](https://cmake.org/cmake/help/latest/envvar/DESTDIR.html)
  is used by the Makefile to install to a nonstandard location.

Example:
If you want to install MOTION to `~/path/to/motion/prefix/{include,lib}` you can use:
```
cmake .. -DCMAKE_INSTALL_PREFIX=""
make
make DESTDIR=~/path/to/motion/prefix install
```
or
```
cmake .. -DCMAKE_INSTALL_PREFIX=~/path/to/motion/prefix
make
make install
```

##### Docker setup

1. Create a Docker image. This may take a few minutes, but you will only have to do this once.
    ```
   docker build -t motion .
    ```

2. Run the Docker image.
    ```
   docker run -it --rm motion
    ```
To check correctness, run the test using `--gtest_filter='-*ipv6*'` because Docker doesn't support IPv6 by default.
#### Developer Guide and Documentation
**TODO (in work):** We provide an extensive developer guide with many examples and explanations of how to use MOTION.

Also, for further information see comments on the code and the [online doxygen documentation for MOTION](https://motion-documentation.github.io). 
Alternatively, it can be built locally in `your_build_folder/doc` by adding `-DMOTION_BUILD_DOC=On` to the `cmake` command.


### MOTION Applications

---


#### Running Applications
  Adding `-DMOTION_BUILD_EXE=On` to the `cmake` command enables the compilation of the applications implemented in 
  MOTION. Currently, the following applications are implemented and can be found in `src/examples/`:
  * AES-128 encryption
  * SHA-256 hashing
  * millionaires' problem: each party has an integer input (amount of money), the protocol yields the index of the party 
  with the largest input (i.e., the richest party)
  * **TODO (in work, cleanup):** All the applications implemented in [HyCC](https://gitlab.com/securityengineering/HyCC) 
  via our HyCC adapter
    
Three other examples with a detailed `README` can be found in `src/examples/tutorial/` :
  * Crosstabs
  * Inner Product
  * Multiply 3: multiply three real inputs from three parties or three shared inputs from two parties.
