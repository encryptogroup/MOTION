#ifndef SHARE_H
#define SHARE_H

#include <memory>

#include "utility/typedefs.h"
#include "wire/wire.h"

namespace ABYN::Shares {

    class Share {
    protected:
    public:
        virtual Protocol GetSharingType() = 0;

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
        ArithmeticWirePtr<T> value;
    public:
        virtual std::vector<T> &GetValue() final { return value->GetRawValues(); };

        virtual Protocol GetSharingType() final { return value->GetProtocol(); }

        virtual bool IsConstantShare() final { return false; };

        auto GetValueByteLength() { return sizeof(T); };

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

        virtual Protocol GetSharingType() final { return ArithmeticGMW; }

        virtual bool IsConstantShare() final { return true; };

        ArithmeticConstantShare(T input) { value = input; };

        ~ArithmeticConstantShare() {};
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    using ArithmeticConstantSharePointer = std::shared_ptr<ArithmeticConstantShare<T>>;

}
#endif //SHARE_H
