# get MOTION
git clone --recursive --config core.autocrlf=input https://github.com/encryptogroup/MOTION.git
cd MOTION
# build MOTION
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DMOTION_BUILD_TESTS=On -DMOTION_BUILD_EXE=On -j 4 ..
make -j 4
