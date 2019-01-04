#ifndef WIRE_H
#define WIRE_H

#include <cstdlib>

namespace ABYN{

class Wire{
public:
    size_t GetNumOfParallelValues(){return num_of_parallel_values;}
protected:
private:
    size_t num_of_parallel_values = 0;
};

}

#endif //WIRE_H