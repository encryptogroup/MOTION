#include "logger.h"


loggert& default_logger()
{
	static loggert logger;
	return logger;
}
