#include <circuit-utils/circuit.hpp>

#include <iostream>


namespace circ {

std::ifstream open_file(std::string const &filename)
{
	std::ifstream input_file(filename);
	if(!input_file)
		throw std::runtime_error{"Failed to open file: " + filename};

	return input_file;
}


// Parsing functions
//==================================================================================================
void cbmc_read_gates(Circuit &circ, std::string const &path) {
	std::ifstream input_file = open_file(path + "/output.gate.txt");
	std::string line;
	GateID gate_id{0};
	while (std::getline(input_file, line)) {

		if(gate_id.value == circ.gates.size())
			break;

		const char* c_str = line.c_str();
		char c_line[strlen(c_str)+1];
		strcpy(c_line, c_str);

		char *gate_type = strtok(c_line, " ");
		char *p = strtok(NULL, " "); // Ignore in Bins
		p = strtok(NULL, " ");

		std::vector<char*> outputs;
		while (p) {
			outputs.push_back(p);      
			p = strtok(NULL, " ");
		}

		// Every gate must have an output.
		assert(outputs.size() > 0);

		// Parse Gate type
		GateKind gate_kind;
		if(gate_type[0] == 'A') {
			gate_kind = GateKind::and_gate;
		} else if(gate_type[0] == 'X') {
			gate_kind = GateKind::xor_gate;
		} else if(gate_type[0] == 'O') {
			gate_kind = GateKind::or_gate;
		}  else if(gate_type[0] == 'N') {
			gate_kind = GateKind::not_gate;
		} else {
			throw std::runtime_error{std::string{"Error, unkown gate type found: "} + gate_type};
		}

		circ[gate_id].kind = gate_kind;

		// Decode outputs
		for(size_t i = 0; i < outputs.size(); i++) {
			p = strtok(outputs[i],":");
			p = strtok(NULL, ":");
			assert(p);
			int32_t out_to = atoi(p);
			assert(out_to != 0);
			if(out_to > 0)
				circ.add_wire(gate_id, GateID(out_to - 1));
			else
				circ.add_wire(gate_id, OutputID(-out_to - 1));
		}

		gate_id.value++;
	}

}

bool is_input_from(std::vector<std::pair<uint64_t, uint64_t>> const &ranges, uint64_t input)
{
	for(auto const &pair: ranges)
	{
		if(input >= pair.first && input < pair.second)
			return true;
	}

	return false;
}

void cbmc_read_inputs(Circuit &circ, std::string const &path)
{
	std::ifstream input_file_a = open_file(path + "/output.inputs.partyA.txt");
	std::ifstream input_file_b = open_file(path + "/output.inputs.partyB.txt");

	std::vector<std::pair<uint64_t, uint64_t>> alice_input_ranges;
	std::vector<std::pair<uint64_t, uint64_t>> bob_input_ranges;

	std::string line;
	uint64_t num_inputs = 0;
	while (std::getline(input_file_a, line))
	{
		std::string var_name;
		int idx_from, bit_width;
		std::istringstream iss(line);
		if (!(iss >> var_name >> idx_from >> bit_width)) { 
			break; // done
		} 

		std::vector<InputID> inputs;
		for(int i = 0; i < bit_width; ++i)
			inputs.push_back(InputID(i + idx_from - 1));
		circ.add_input_variable(Party::alice, var_name, std::move(inputs));

		alice_input_ranges.push_back({idx_from - 1, idx_from + bit_width - 1});
		num_inputs += bit_width;
	}
	while (std::getline(input_file_b, line))
	{
		std::string var_name;
		int idx_from, bit_width;
		std::istringstream iss(line);
		if (!(iss >> var_name >> idx_from >> bit_width)) { 
			break; // done
		} 

		std::vector<InputID> inputs;
		for(int i = 0; i < bit_width; ++i)
			inputs.push_back(InputID(i + idx_from - 1));
		circ.add_input_variable(Party::bob, var_name, std::move(inputs));

		bob_input_ranges.push_back({idx_from - 1, idx_from + bit_width - 1});
		num_inputs += bit_width;
	}

	std::ifstream input_file(path + "/output.inputs.txt");
	uint64_t input_id = 0;
	circ.inputs.resize(num_inputs);
	while (std::getline(input_file, line))
	{
		const char* c_str = line.c_str();
		char c_line[strlen(c_str)+1];
		strcpy(c_line, c_str);

		strtok(c_line, "#"); // Ignore input type
		char *p = strtok(NULL, " "); // Ignore in Bins
		uint64_t parsed_id = atoi(p);
		assert(parsed_id == input_id + 1);

		if(is_input_from(alice_input_ranges, input_id))
			circ.inputs[input_id] = Party::alice;
		else if(is_input_from(bob_input_ranges, input_id))
			circ.inputs[input_id] = Party::bob;
		else
			throw std::runtime_error{"Input is not associated with any party"};

		p = strtok(NULL, " ");
		while(p != NULL) {
			int out_pin, out_gate_id, in_pin;
			if(sscanf(p, "%d:%d:%d", &out_pin, &out_gate_id, &in_pin) != 3)
				throw std::runtime_error{"Invalid input specification"};

			assert(out_gate_id != 0);

			if(out_gate_id > 0)
				circ.add_wire(InputID{input_id}, GateID(out_gate_id - 1));
			else
				circ.add_wire(InputID{input_id}, OutputID(-out_gate_id - 1));

			p = strtok(NULL, " ");
		}
		input_id++;
	}

}

void cbmc_read_constants(Circuit &circ, std::string const &path)
{
	std::ifstream input_file = open_file(path + "/output.constants.txt");   

	uint64_t constant_id = 0;
	std::string line;
	while (std::getline(input_file, line))
	{
		const char* c_str = line.c_str();
		char c_line[strlen(c_str)+1];
		strcpy(c_line, c_str);

		char *const_type = strtok(c_line, " ");
		if(!const_type)
			break;
		assert(const_type[0] == 'O');
		char* p = strtok(NULL, " ");

		while(p != NULL) {
			char gate_out[strlen(p)+1];
			memset(gate_out, 0, strlen(p)+1);
			int diff = strrchr(p, ':') - strchr(p, ':') - 1;
			char *start = strchr(p, ':') + 1;
			assert(diff > 0);
			strncpy(gate_out, start, diff);
			int32_t out_gate_id = atoi(gate_out);
			assert(out_gate_id != 0);

			if(out_gate_id > 0)
				circ.add_wire(const_one_id(), GateID(out_gate_id - 1));
			else
				circ.add_wire(const_one_id(), OutputID(-out_gate_id - 1));

			p = strtok(NULL, " ");
		}

		constant_id++;
	}
}

void cbmc_read_outputs(Circuit &circ, std::string const &path)
{
	std::vector<uint64_t> res;
	std::ifstream input_file = open_file(path + "/output.mapping.txt");

	std::string line;
	uint64_t num_outputs = 0;
	while (std::getline(input_file, line)) {
		const char* c_str = line.c_str();
		char c_line[strlen(c_str)+1];
		strcpy(c_line, c_str);

		std::string var_name = strtok(c_line, " ");
		char *p = strtok(NULL, " "); // Ignore DATATYPE
		p = strtok(NULL, " ");

		std::vector<OutputID> ids;
		while (p) {
			OutputID id(atoi(p) - 1);
			ids.push_back(id);
			p = strtok(NULL, " ");
		}

		num_outputs += ids.size();
		circ.add_output_variable(var_name, std::move(ids));
	}

	circ.outputs.resize(num_outputs);
}

void cbmc_read_debug(Circuit &circ, std::string const &path)
{
	/*std::ifstream input_file(path + "/output.debug.txt");
	if(!input_file)
		return;

	while(input_file)
	{
		std::string msg;
		if(!std::getline(input_file, msg))
			break;

		std::string type_str;
		std::getline(input_file, type_str);

		std::vector<ElementID> bits;
		std::string in_wires;
		std::getline(input_file, in_wires);
		std::stringstream ss{in_wires};
		std::string in;
		while(ss >> in)
		{
			if(in == "ONE")
				bits.push_back(ElementID{circ.get_or_create_constant_one()});
			else if(in == "ZERO")
				bits.push_back(ElementID{circ.get_or_create_constant_zero()});
			else if(in[0] == 'B' || in[0] == 'A')
				bits.push_back(ElementID{InputID(std::stoi(in.substr(9)) - 1)});
			else if(in[0] == '-')
				bits.push_back(ElementID{OutputID(std::stoi(in.substr(1)) - 1)});
			else
			{
				try {
					bits.push_back(ElementID{GateID(std::stoi(in) - 1)});
				}
				catch(...) {
					std::cout << "failed to convert integer \"" << in << '"' << std::endl;
					throw;
				}
			}
		}

		Type type;
		if(type_str == "raw")
			type = Type{BitsType{(int)bits.size()}};
		else if(type_str == "signed")
			type = Type{IntegerType{true, (int)bits.size()}};
		else if(type_str == "unsigned")
			type = Type{IntegerType{false, (int)bits.size()}};
		else
			throw std::runtime_error{"Unknown type: " + type_str};

		circ.debug_messages.push_back({msg, type, bits});
	}*/
}

void cbmc_read_spec(Circuit &circ, std::string const &path)
{
	std::ifstream input_file(path + "/output.spec.txt");

	std::string line;
	while(std::getline(input_file, line))
	{
		ParseState parser{line.c_str(), "output.spec.txt"};
		auto name = to_str(accept(parser, TokenKind::identifier).text);
		accept(parser, TokenKind::colon);

		auto input_it = circ.name_to_inputs.find(name);
		auto output_it = circ.name_to_outputs.find(name);
		if(input_it != circ.name_to_inputs.end())
			input_it->second.type = parse_type(parser);
		else if(output_it != circ.name_to_outputs.end())
			output_it->second.type = parse_type(parser);
		else
			throw std::runtime_error{"Unknown variable name: " + name};

		accept(parser, TokenKind::semicolon);
	}
}

Circuit read_cbmc_circuit(std::string const &path)
{
	std::ifstream number_of_gates_file = open_file(path + "/output.numberofgates.txt");
	uint64_t num_gates;
	number_of_gates_file >> num_gates;

	Circuit circ;
	circ.gates.resize(num_gates);

	cbmc_read_outputs(circ, path);
	cbmc_read_gates(circ, path);
	cbmc_read_inputs(circ, path);
	cbmc_read_constants(circ, path);
	cbmc_read_debug(circ, path);
	cbmc_read_spec(circ, path);

	return circ;
}


// C code export
//==================================================================================================
static void create_input_gates_for_var(std::ostream &os, Type const &type, std::string const &path,
                                       std::vector<InputID> const &inputs, size_t *idx)
{
	switch(type.kind())
	{
		case TypeKind::integer:
		case TypeKind::bits:
		{
			size_t width = get_bit_width(type);
			assert(*idx + width <= inputs.size());

			for(size_t i = 0; i < width; ++i)
				os << "\t_Bool input_" << inputs[*idx+i].value << " = (" << path + " >> " + std::to_string(i) << ") & 1;\n";

			*idx += width;
		} break;

		case TypeKind::array:
		{
			auto arr_type = get_array_type(type);
			for(int i = 0; i < arr_type->length; ++i)
				create_input_gates_for_var(os, *arr_type->sub, path + '[' + std::to_string(i) + ']', inputs, idx);
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto const &m: struct_type->members)
				create_input_gates_for_var(os, *m.second, path + '.' + m.first, inputs, idx);
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
		create_input_gates_for_var(os, info.type, name, info.inputs, &idx);
	}
}

static std::string create_parameter_list(Circuit const &circ)
{
	InputVarIterator it_a, it_b;
	std::tie(it_a, it_b) = get_alice_and_bob(circ);
	return "InputA " + it_a->first + ", InputB " + it_b->first;
}

static void assign_gates_to_out_var(std::ostream &os, Type const &type, std::string const &path,
                                    std::vector<OutputID> const &outputs, size_t *idx)
{
	switch(type.kind())
	{
		case TypeKind::integer:
		case TypeKind::bits:
		{
			size_t width = get_bit_width(type);
			assert(*idx + width <= outputs.size());

			for(size_t i = 0; i < width; ++i)
				os << "\t" << path << " = " << path << " | ((unsigned long long)output_" << outputs[*idx+i].value << " << " << i << ");\n";

			*idx += width;
		} break;

		case TypeKind::array:
		{
			auto arr_type = get_array_type(type);
			for(int i = 0; i < arr_type->length; ++i)
				assign_gates_to_out_var(os, *arr_type->sub, path + '[' + std::to_string(i) + ']', outputs, idx);
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto const &m: struct_type->members)
				assign_gates_to_out_var(os, *m.second, path + '.' + m.first, outputs, idx);
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
		assign_gates_to_out_var(os, info.type, name, info.outputs, &idx);
	}
}

static void zero_output_variables(std::ostream &os, Circuit const &circ)
{
	for(auto const &pair: circ.name_to_outputs)
	{
		auto const &name = pair.first;
		auto const &info = pair.second;
		auto num_bits = get_bit_width(info.type);
		assert(num_bits % 8 == 0);
		os << "\tmemset(&" << name << ", 0, " << (num_bits / 8) << ");\n";
	}
}

static void convert_gate(
	std::ostream &os, std::unordered_map<ElementID, std::string> &element_map,
	Circuit const &circ, GateID id)
{
	Gate const &gate = circ[id];
	auto gate_name = "gate_" + std::to_string(id.value);
	switch(gate.kind)
	{
		case GateKind::not_gate:
		{
			assert(gate.num_fanins == 1);
			os << "\t_Bool " << gate_name << " = !" << element_map[gate.fanins[0]] << ";\n";
			element_map[id] = gate_name;
		} break;
		case GateKind::and_gate:
		{
			assert(gate.num_fanins == 2);
			auto in_a = gate.fanins[0];
			auto in_b = gate.fanins[1];
			os << "\t_Bool " << gate_name << " = " << element_map[in_a] << " & " << element_map[in_b] << ";\n";
			element_map[id] = gate_name;
		} break;
		case GateKind::or_gate:
		{
			assert(gate.num_fanins == 2);
			auto in_a = gate.fanins[0];
			auto in_b = gate.fanins[1];
			os << "\t_Bool " << gate_name << " = " << element_map[in_a] << " | " << element_map[in_b] << ";\n";
			element_map[id] = gate_name;
		} break;
		case GateKind::xor_gate:
		{
			assert(gate.num_fanins == 2);
			auto in_a = gate.fanins[0];
			auto in_b = gate.fanins[1];
			os << "\t_Bool " << gate_name << " = " << element_map[in_a] << " ^ " << element_map[in_b] << ";\n";
			element_map[id] = gate_name;
		} break;
	}
}

static void convert_element(std::ostream &os, Circuit const &circ, std::unordered_map<ElementID, std::string> &element_map, ElementID id)
{
	switch(id.kind())
	{
		case ElementID::Kind::const_one:
		{
			os << "\t_Bool const_one = 1;\n";
			element_map[id] = "const_one";
		} break;
		case ElementID::Kind::gate:
			convert_gate(os, element_map, circ, id.as_gate_id());
			break;
		case ElementID::Kind::input:
			element_map[id] = "input_" + std::to_string(id.id());
			break;
		case ElementID::Kind::output:
		{
			auto const &opt_fanin = circ.outputs[id.id()];
			assert(opt_fanin);

			auto name = "output_" + std::to_string(id.id());
			os << "\t_Bool " << name << " = " << element_map[*opt_fanin] << ";\n";
			element_map[id] = name;
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

	std::unordered_map<ElementID, std::string> element_map;
	create_input_gates(os, circ);
	topological_traversal(circ, [&](ElementID id)
	{
		convert_element(os, circ, element_map, id);
	});
	assign_gates_to_outputs(os, circ);

	os << "\n\treturn " << out_var_name << ";\n}\n";
}

}
