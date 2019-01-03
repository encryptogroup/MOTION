#ifndef ABYNCONFIGURATION_H
#define ABYNCONFIGURATION_H

#include <vector>
#include <cstdarg>
#include <memory>

#include "party.h"

namespace ABYN {

    class ABYNConfiguration {
    private:
        std::vector<Party> parties;

        ABYNConfiguration() {};
    public:
        ABYNConfiguration(std::vector<Party> &parties) { this->parties = std::vector(parties); };
        ABYNConfiguration(std::initializer_list<Party> list_parties) {this->parties = std::vector(list_parties); };

        ~ABYNConfiguration() {};

        std::vector<Party> & GetParties(){return parties;};
        Party & GetParty(uint i){return parties.at(i);}
    };

    using ABYNConfigurationPtr = std::shared_ptr<ABYNConfiguration>;

}

#endif //ABYNCONFIGURATION_H
