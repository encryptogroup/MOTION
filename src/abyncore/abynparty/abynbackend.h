#ifndef ABYNBACKEND_H
#define ABYNBACKEND_H

#include <memory>
#include "utility/abynconfiguration.h"

namespace ABYN {

    class ABYNBackend {

    private:
        ABYNBackend() {};
        ABYNConfigurationPtr abyn_config;

    protected:

    public:
        ABYNBackend(ABYNConfigurationPtr abyn_config) { this->abyn_config = abyn_config; };

    };

    using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
