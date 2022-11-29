#include <circuit-utils/circuit_io.hpp>

#include <libcircuit/type.h>


namespace circ {

// C code export
//==================================================================================================
static char const* width_to_c_type(uint8_t width)
{
	switch(width)
	{
		case 1: return "_Bool";
		case 8: return "uint8_t";
		case 16: return "uint16_t";
		case 32: return "uint32_t";
		case 64: return "uint64_t";

		default: assert(0);
	}
}

static char const* width_to_bit_mask(uint8_t width)
{
	switch(width)
	{
		case 1: return "0x1";
		case 8: return "0xff";
		case 16: return "0xffff";
		case 32: return "0xffffffff";
		case 64: return "0xffffffffffffffff";

		default: assert(0);
	}
}

void ignore_inputs(Circuit const &circ, std::vector<InputID> const &inputs, size_t *idx, int width)
{
	while(*idx < inputs.size() && width > 0)
	{
		int input_width = circ.get_width(inputs[*idx]);
		assert(input_width <= width);

		width -= input_width;
		++*idx;
	}

	assert(width == 0);
}

static void create_input_gates_for_var(std::ostream &os, Circuit const &circ, Type const &type, std::string const &path,
                                       std::vector<InputID> const &inputs, size_t *idx)
{
	switch(type.kind())
	{
		case TypeKind::integer:
		case TypeKind::boolean:
		case TypeKind::bits:
		{
			size_t total_width = get_bit_width(type);

			// For each input gate, create a C variable with the appropriate width
			for(size_t cur_width = 0; cur_width < total_width; *idx += 1)
			{
				assert(*idx < inputs.size());
				uint8_t input_width = circ.get_width(inputs[*idx]);

				os << '\t' << width_to_c_type(input_width) << " input_" << inputs[*idx].value
				   << " = (" << path + " >> " + std::to_string(cur_width) << ") & " << width_to_bit_mask(input_width) << ";\n";

				cur_width += input_width;
			}
		} break;

		case TypeKind::array:
		{
			auto arr_type = get_array_type(type);
			for(int i = 0; i < arr_type->length; ++i)
				create_input_gates_for_var(os, circ, *arr_type->sub, path + '[' + std::to_string(i) + ']', inputs, idx);
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto const &m: struct_type->members)
			{
				// CBMC inserts special $pad members for padding if necessary. They are usually not
				// accessed so we ignore them. (This makes things easier since they usually have a
				// bit-width not natively supported by C.)
				if(starts_with(m.first, "$pad"))
				{
					ignore_inputs(circ, inputs, idx, get_bit_width(*m.second));
					continue;
				}

				create_input_gates_for_var(os, circ, *m.second, path + '.' + m.first, inputs, idx);
			}
		} break;
	}
}

static void create_input_gates(std::ostream &os, Circuit const &circ)
{
	if(circ.name_to_inputs.size() != 2)
		throw std::runtime_error{
			"Right now, code generation is only supported for circuits with exactly one input per party"
		};

	for(auto const &pair: circ.name_to_inputs)
	{
		auto const &name = pair.first;
		auto const &info = pair.second;
		size_t idx = 0;
		create_input_gates_for_var(os, circ, info.type, name, info.inputs, &idx);
	}
}

static char const* type_name_for_party(Party p)
{
	switch(p)
	{
		case Party::alice: return "InputA";
		case Party::bob: return "InputB";
	}
}

static std::string create_parameter_list(Circuit const &circ)
{
	if(circ.name_to_inputs.size() != 2)
		throw std::runtime_error{
			"Right now, code generation is only supported for circuits with exactly one input per party"
		};

	auto type_0 = type_name_for_party(circ.ordered_inputs[0]->party);
	auto const &name_0 = circ.ordered_inputs[0]->name;
	auto type_1 = type_name_for_party(circ.ordered_inputs[1]->party);
	auto const &name_1 = circ.ordered_inputs[1]->name;

	return std::string{type_0} + ' ' + name_0 + ", " + type_1 + ' ' + name_1;
}

static void assign_gates_to_out_var(std::ostream &os, Circuit const &circ, Type const &type, std::string const &path,
                                    std::vector<OutputID> const &outputs, size_t *idx)
{
	switch(type.kind())
	{
		case TypeKind::integer:
		case TypeKind::boolean:
		case TypeKind::bits:
		{
			size_t total_width = get_bit_width(type);

			for(size_t cur_width = 0; cur_width < total_width; *idx += 1)
			{
				assert(*idx < outputs.size());
				uint8_t output_width = circ.get_width(outputs[*idx]);

				os << '\t' << path << " |= " << " (" << width_to_c_type(output_width)
				   << ")(output_" << outputs[*idx].value << " & " << width_to_bit_mask(output_width) << ") << " << cur_width << ";\n";

				cur_width += output_width;
			}
		} break;

		case TypeKind::array:
		{
			auto arr_type = get_array_type(type);
			for(int i = 0; i < arr_type->length; ++i)
				assign_gates_to_out_var(os, circ, *arr_type->sub, path + '[' + std::to_string(i) + ']', outputs, idx);
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto const &m: struct_type->members)
				assign_gates_to_out_var(os, circ, *m.second, path + '.' + m.first, outputs, idx);
		} break;
	}
}

static void assign_gates_to_outputs(std::ostream &os, Circuit const &circ)
{
	for(auto const &pair: circ.name_to_outputs)
	{
		auto const &name = pair.first;
		auto const &info = pair.second;
		size_t idx = 0;
		assign_gates_to_out_var(os, circ, info.type, name, info.outputs, &idx);
	}
}

static void zero_output_variables(std::ostream &os, Circuit const &circ)
{
	for(auto const &pair: circ.name_to_outputs)
	{
		auto const &name = pair.first;
		os << "\tmemset(&" << name << ", 0, sizeof(" << name << "));\n";
	}
}

static char const* gate_to_c_op(GateKind k)
{
	switch(k)
	{
		case GateKind::not_gate: return "!";
		case GateKind::and_gate: return "&";
		case GateKind::or_gate: return "|";
		case GateKind::xor_gate: return "^";

		case GateKind::add_gate: return "+";
		case GateKind::sub_gate: return "-";
		case GateKind::neg_gate: return "-";
		case GateKind::mul_gate: return "*";

		default: assert(0);
	}
}

static void convert_gate(
	std::ostream &os, std::unordered_map<WireEndpoint, std::string> &element_map,
	Circuit const &circ, GateID id)
{
	Gate const &gate = circ[id];
	auto gate_name = "gate_" + std::to_string(id.value);
	switch(gate.kind)
	{
		// Unary gates
		case GateKind::not_gate:
		case GateKind::neg_gate:
		{
			assert(gate.num_fanins == 1);

			os << '\t' << width_to_c_type(gate.width) << ' ' << gate_name << " = "
			   << gate_to_c_op(gate.kind) << element_map[gate.fanins[0]] << ";\n";

			element_map[primary_endpoint(id)] = gate_name;
		} break;

		// Binary gates
		case GateKind::and_gate:
		case GateKind::or_gate:
		case GateKind::xor_gate:
		case GateKind::add_gate:
		case GateKind::sub_gate:
		case GateKind::mul_gate:
		{
			assert(gate.num_fanins == 2);
			auto in_a = gate.fanins[0];
			auto in_b = gate.fanins[1];

			os << '\t' << width_to_c_type(gate.width) << ' ' << gate_name << " = "
			   << element_map[in_a] << ' ' << gate_to_c_op(gate.kind) << ' ' << element_map[in_b] << ";\n";

			element_map[primary_endpoint(id)] = gate_name;
		} break;

		case GateKind::one_gate:
		{
			os << "\t_Bool const_one = 1;\n";
			element_map[primary_endpoint(id)] = "const_one";
		} break;

		case GateKind::const_gate:
		{
			os << '\t' << width_to_c_type(gate.width) << ' ' << gate_name << " = " << gate.const_value << ";\n";
			element_map[primary_endpoint(id)] = gate_name;
		} break;

		case GateKind::combine_gate:
		{
			os << '\t' << width_to_c_type(gate.width) << ' ' << gate_name << " = 0;\n";
			for(uint8_t i = 0; i < gate.width; ++i)
				os << '\t' << gate_name << " |= (" << width_to_c_type(gate.width) << ")(" << element_map.at(gate.fanins[i]) << ") << " << (int)i << ";\n";

			element_map[primary_endpoint(id)] = gate_name;
		} break;

		case GateKind::split_gate:
		{
			uint8_t width = circ.get_width(gate.fanins[0].id);
			for(uint8_t i = 0; i < width; ++i)
			{
				std::string ep_name = gate_name + '_' + std::to_string(i);
				os << '\t' << width_to_c_type(gate.width) << ' ' << ep_name << " = (" << element_map.at(gate.fanins[0]) << " >> " << (int)i << ") & 1;\n";
				element_map[{id, i}] = ep_name;
			}
		} break;
		
		default:
			throw std::runtime_error{"convert_gate: gate kind not implemented yet"};
	}
}

static void convert_element(std::ostream &os, Circuit const &circ, std::unordered_map<WireEndpoint, std::string> &element_map, ElementID id)
{
	switch(id.kind())
	{
		case ElementID::Kind::gate:
			convert_gate(os, element_map, circ, id.as_gate_id());
			break;
		case ElementID::Kind::input:
			element_map[primary_endpoint(id)] = "input_" + std::to_string(id.id());
			break;
		case ElementID::Kind::output:
		{
			auto const &opt_fanin = circ.outputs[id.id()];
			assert(opt_fanin);

			auto name = "output_" + std::to_string(id.id());
			os << '\t' << width_to_c_type(circ.get_width(id)) << ' ' << name << " = " << element_map[*opt_fanin] << ";\n";
			element_map[primary_endpoint(id)] = name;
		} break;
	}
}

void to_c_code(std::ostream &os, Circuit const &circ, std::string const &func_name)
{
	if(circ.name_to_outputs.size() != 1)
		throw std::runtime_error{"Currently, only functions with a single output variables are supported"};

	os << "Output " << func_name << "(" +create_parameter_list(circ) + ")\n{\n";

	auto out_var_name = circ.name_to_outputs.begin()->first;
	os << "\tOutput " << out_var_name << ";\n";
	// TODO Outputs are set to zero to make it easier to set individual bits. This is only okay as
	//      long as all bits are set, otherwise it would influence the result.
	zero_output_variables(os, circ);

	std::unordered_map<WireEndpoint, std::string> element_map;
	create_input_gates(os, circ);
	topological_traversal(circ, [&](ElementID id)
	{
		convert_element(os, circ, element_map, id);
	});
	assign_gates_to_outputs(os, circ);

	os << "\n\treturn " << out_var_name << ";\n}\n";
}

}
