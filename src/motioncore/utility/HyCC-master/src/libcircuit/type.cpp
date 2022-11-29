#include "type.h"

#include <sstream>


//==================================================================================================
static void type_to_string(Type const &t, std::string &out)
{
	switch(t.kind())
	{
		case TypeKind::bits:
		{
			out = "bits#" + std::to_string(t.bits().width) + out;
		} break;

		case TypeKind::boolean:
		{
			out = "bool" + out;
		} break;

		case TypeKind::integer:
		{
			char const *type_name = t.integer().is_signed ? "int" : "uint";
			out = type_name + std::to_string(t.integer().width) + out;
		} break;

		case TypeKind::array:
		{
			out += '[' + std::to_string(t.array().length) + ']';
			type_to_string(*t.array().sub, out);
		} break;

		case TypeKind::structure:
		{
			std::string struct_str;
			for(auto const &mem: t.structure().members)
				struct_str += mem.first + ": " + str(*mem.second) + "; ";

			out = '{' + struct_str + '}' + out;
		} break;
	}
}

std::ostream& operator << (std::ostream &os, Type const &t)
{
	std::string str;
	type_to_string(t, str);
	return os << str;
}

std::string str(Type const &t)
{
	std::ostringstream os;
	os << t;
	return os.str();
}

