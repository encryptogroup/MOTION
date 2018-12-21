#ifndef SHARE_H
#define SHARE_H

#include "utility/typedefs.h"
#include <memory>

namespace ABYN::Shares{
class Share {
public:
    Share() {};

    virtual ~Share() {};
};

typedef std::shared_ptr<Share> SharePointer;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticShare : public Share {
protected:
    T value;
public:
    virtual T GetValue() final {return value;};

    ArithmeticShare(T input) { value = input; };

    ~ArithmeticShare() {};
};


template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticSharePointer = std::shared_ptr<ArithmeticShare<T>>;

}
#endif //SHARE_H
