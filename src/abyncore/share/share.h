#ifndef SHARE_H
#define SHARE_H

#include <memory>

#include "utility/typedefs.h"

namespace ABYN::Shares {



    class Share {
    protected:
    public:
        virtual ShareType GetShareType() = 0;

        virtual bool IsConstantShare() = 0;

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
        virtual T GetValue() final { return value; };

        virtual ShareType GetShareType() final { return ArithmeticShareType; }

        virtual bool IsConstantShare() final { return false; };

        ArithmeticShare(T input) { value = input; };

        ~ArithmeticShare() {};
    };


    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    using ArithmeticSharePointer = std::shared_ptr<ArithmeticShare<T>>;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    class ArithmeticConstantShare : public Share {
    private:
        ArithmeticConstantShare() {};
    protected:
        T value;
    public:
        virtual T GetValue() final { return value; };

        virtual ShareType GetShareType() final { return ArithmeticShareType; }

        virtual bool IsConstantShare() final { return true; };

        ArithmeticConstantShare(T input) { value = input; };

        ~ArithmeticConstantShare() {};
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    using ArithmeticConstantSharePointer = std::shared_ptr<ArithmeticConstantShare<T>>;

}
#endif //SHARE_H
