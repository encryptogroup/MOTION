#ifndef ABYNPARTY_H
#define ABYNPARTY_H

#include <vector>
#include <memory>

#include "utility/abynconfiguration.h"
#include "abynbackend.h"
#include "gate/gate.h"
//#include "OTExtension/ot/ot-ext.h"

namespace ABYN {

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    using ArithmeticSharePointer = ABYN::Arithmetic::ArithmeticSharePointer<T>;

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    using ArithmeticShare = ABYN::Arithmetic::ArithmeticShare<T>;

    class ABYNParty {

    private:
        ABYNConfigurationPtr configuration;
        ABYNBackendPtr backend;

    protected:
        ABYNParty() {};

    public:

        ABYNParty(std::vector<Party> &parties) {
            configuration = ABYNConfigurationPtr(new ABYNConfiguration(parties));
            backend = ABYNBackendPtr(new ABYNBackend(configuration));
        };

        ABYNParty(std::initializer_list<Party> list_parties) {
            configuration = ABYNConfigurationPtr(new ABYNConfiguration(list_parties));
            backend = ABYNBackendPtr(new ABYNBackend(configuration));
        }

        ABYNParty(ABYNConfigurationPtr configuration) { this->configuration = configuration; };

        ~ABYNParty() {};

        ABYNConfigurationPtr GetConfiguration() { return configuration; };

        template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
        ArithmeticSharePointer<T> ShareArithmeticInput(T input){
            auto p = ABYN::Gates::Arithmetic::ArithmeticInputGate(input, backend);
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(input)>>(s);
            return sa;
        }
    };

    using ABYNPartyPtr = std::unique_ptr<ABYNParty>;

}
#endif //ABYNPARTY_H
