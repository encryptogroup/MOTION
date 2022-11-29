#include "circuit_converter.h"


namespace {

//==================================================================================================
simple_circuitt::gatet* get_combiner_of_input(simple_circuitt::gatet const *input)
{
	assert(input->get_operation() == simple_circuitt::INPUT);

	// The combiner must be the INPUT's only fanout, otherwise we wouldn't be able to replace the
	// INPUT. (If the INPUT is connected to multiple equivalent COMBINERs we actually could replace
	// the INPUT, but it's is more work. Let's hope that equivalent COMBINERs are always optimized
	// out.)
	if(input->get_fanouts().size() == 1)
	{
		auto fanout = input->get_fanouts()[0]->second.gate;
		if(fanout->get_operation() == simple_circuitt::COMBINE)
			return fanout;
	}

	return nullptr;
}


template<typename It>
It find_next_input_connected_to_combiner(It begin, It end)
{
	while(begin != end && !get_combiner_of_input(*begin))
		++begin;

	return begin;
}

template<typename It>
void remove_gates(simple_circuitt &circuit, It begin, It end)
{
	while(begin != end)
	{
		circuit.remove(*begin);
		++begin;
	}
}

// A COMBINER can be replaced by a single INPUT of the same width iff
// - all the COMBINER's fanins are INPUTs that belong to the same variable and
// - the order of the fanins is the same as the order of the INPUTs as they occur in their variable
template<typename It>
optional<It> combiner_replaceable_by_new_input(
	simple_circuitt::gatet *combiner,
	It inputs_begin, It inputs_end)
{
	for(auto fanin: combiner->fanin_range())
	{
		(void)fanin;
		if(inputs_begin == inputs_end)
			return emptyopt;

		if(get_combiner_of_input(*inputs_begin) != combiner)
			return emptyopt;

		++inputs_begin;
	}

	return inputs_begin;
}

}


//==================================================================================================
void replace_input_combiners(simple_circuitt &circuit, loggert &logger)
{
	for(simple_circuitt::variablet &var: circuit.variables())
	{
		if(var.owner == variable_ownert::output)
			continue;

		auto input_it = var.gates.begin();
		while(true)
		{
			input_it = find_next_input_connected_to_combiner(input_it, var.gates.end());
			if(input_it == var.gates.end())
				break;

			simple_circuitt::gatet *combiner = (*input_it)->get_fanouts()[0]->second.gate;
			auto combiner_inputs_end_opt = combiner_replaceable_by_new_input(
				combiner,
				input_it,
				var.gates.end());

			if(combiner_inputs_end_opt)
			{
				logger.debug() << "Replacing " << combiner->get_width() << "bit combiner with new input" << eom;
				auto new_input = circuit.create_input_gate("", combiner->get_width());
				set_sharing(new_input, e_sharing::S_ARITH);
				combiner->replace_by(new_input);
				circuit.remove(combiner);

				remove_gates(circuit, input_it, *combiner_inputs_end_opt);
				input_it = var.gates.erase(input_it, *combiner_inputs_end_opt);

				var.gates.insert(input_it, new_input);
			}
			else
				++input_it;
		}
	}
}
