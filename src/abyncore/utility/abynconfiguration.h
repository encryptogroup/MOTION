#ifndef ABYNCONFIGURATION_H
#define ABYNCONFIGURATION_H

#include <vector>
#include <cstdarg>
#include <memory>
#include <functional>

#include "party.h"

namespace ABYN {

    class ABYNConfiguration {
    private:
        std::vector<Party> parties;

        ABYNConfiguration() {};

    public:
        ABYNConfiguration(std::vector<Party> &parties) { this->parties = std::move(parties); };

        ABYNConfiguration(std::initializer_list<Party> &list_parties) {
            for (auto &p : list_parties)
                parties.push_back(std::move(p));
        };

        ~ABYNConfiguration() {};

        std::vector<Party> &GetParties() { return parties; };

        size_t GetNumOfParties() { return parties.size(); };

        Party &GetParty(uint i) { return parties.at(i); };

        void AddParty(Party &party) { parties.push_back(std::move(party)); };
    };

    using ABYNConfigurationPtr = std::shared_ptr<ABYNConfiguration>;

}

#endif //ABYNCONFIGURATION_H
