#include "circuit_creator.h"

#include <libcircuit/simple_circuit.h>


//==================================================================================================
Type from_cbmc(typet const &cbmc_type)
{
  if(cbmc_type.id() ==  ID_array)
  {
    array_typet array_type = to_array_type(cbmc_type);

    // Must have a finite size
    mp_integer array_size_mp;
    if(to_integer(array_type.size(), array_size_mp))
      throw std::runtime_error{"failed to convert array size"};

    int array_size = integer2size_t(array_size_mp);

    return ArrayType{from_cbmc(array_type.subtype()), array_size};
  }
  else if(cbmc_type.id() == ID_struct)
  {
    struct_typet struct_type = to_struct_type(cbmc_type);
    auto const &comps = struct_type.components();

    StructType our_type;
    for(size_t i = 0; i < comps.size(); ++i)
      our_type.add_member(comps[i].get_name().c_str(), from_cbmc(comps[i].type()));

    return our_type;
  }
  else if(cbmc_type.id() == ID_signedbv)
    return IntegerType{true, cbmc_type.get_int("width")};
  else if(cbmc_type.id() == ID_unsignedbv)
    return IntegerType{false, cbmc_type.get_int("width")};
  else if(cbmc_type.id() == ID_c_bool)
    return BoolType{};
  else
  {
    std::cout << cbmc_type.pretty() << std::endl;
    assert(!"Invalid input type");
  }
}

