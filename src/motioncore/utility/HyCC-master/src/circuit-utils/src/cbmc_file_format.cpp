#include <circuit-utils/circuit.hpp>


namespace circ {

namespace {


//==================================================================================================
class IDConverter
{
public:
	explicit IDConverter(Circuit *circuit, uint32_t num_inputs, uint32_t num_gates) :
		m_circuit{circuit},
		// `num_gates` is only an estimate of the total number of IDs because SPLIT gates require
		// more than one ID.
		m_id_to_endpoint{num_gates},
		m_num_inputs{num_inputs},
		m_current_gate_id{0} {}

	WireEndpoint get(uint32_t id) const
	{
		if(id < m_num_inputs)
			return primary_endpoint(InputID{id});

		// Okay, the id refers to a gate.
		id -= m_num_inputs;
		assert(id < m_id_to_endpoint.size());

		return m_id_to_endpoint[id];
	}

	void set(uint32_t id, WireEndpoint ep)
	{
		assert(id < m_id_to_endpoint.size());
		m_id_to_endpoint[id] = ep;
	}

	void reserve_split_ids(uint32_t count)
	{
		m_id_to_endpoint.resize(m_id_to_endpoint.size() + count - 1);
	}

private:
	Circuit *m_circuit;
	std::vector<WireEndpoint> m_id_to_endpoint;
	uint32_t m_num_inputs;
	uint32_t m_current_gate_id;
};


//==================================================================================================
Party to_party(uint8_t party)
{
	switch(party)
	{
		case 0: return Party::alice; // Inputs from function calls are assigned to Alice
		case 1: return Party::alice;
		case 2: return Party::bob;
		default: throw std::runtime_error{"Unsupported party: " + std::to_string(party)};
	}
}

void read_input_partitioning(RawReader &rr, Circuit &circuit)
{
	auto partitioning = rr.read<uint32_t>();
	uint32_t count = partitioning >> 12;
	uint32_t party = (partitioning >> 8) & 0xf;
	uint8_t width_minus_one = partitioning & 0xff;

	// TODO For now, we only support a maximum width of 128
	assert(!(width_minus_one >> 7));

	uint8_t width = width_minus_one + 1;
	assert(width);

	for(uint32_t i = 0; i < count; ++i)
		circuit.inputs.push_back({to_party(party), width});

}

std::vector<OutputID> read_outputs(RawReader &rr, Circuit &circuit, int total_width, IDConverter const &id_converter)
{
	std::vector<OutputID> outputs;
	int cur_bit_width = 0;
	while(cur_bit_width != total_width)
	{
		WireEndpoint fanin = id_converter.get(rr.read<uint32_t>());
		cur_bit_width += circuit.get_width(fanin.id);

        OutputID oid = circuit.add_output(fanin);
		outputs.push_back(oid);
	}

	return outputs;
}

std::pair<GateKind, uint8_t> read_gate_kind(RawReader &rr)
{
	uint8_t data;
	rr >> data;

	if((data & 0xe0) == 0) // Boolean gate
	{
		switch(data & 0x7)
		{
			case 1: return {GateKind::and_gate, 0};
			case 2: return {GateKind::or_gate, 0};
			case 3: return {GateKind::xor_gate, 0};
			case 4: return {GateKind::not_gate, 0};
			case 5: return {GateKind::one_gate, 0};
			default:
				throw std::runtime_error{"Unknown boolean gate"};
		}
	}
	else if((data & 0xe0) == 0xc0) // Arithmetic gate
	{
		switch(data & 0x7)
		{
			case 1: return {GateKind::add_gate, 0};
			case 2: return {GateKind::sub_gate, 0};
			case 3: return {GateKind::neg_gate, 0};
			case 4: return {GateKind::mul_gate, 0};
			case 5: return {GateKind::const_gate, 0};
			default:
				throw std::runtime_error{"Unknown arithmetic gate"};
		}
	}
	else if((data & 0xc0) == 0x40) // Combine gate
		return {GateKind::combine_gate, (data & 0x3f) + 1};
	else if((data & 0xe0) == 0xe0) // Split gate
		return {GateKind::split_gate, data & 0x2f};
	else
		throw std::runtime_error{"Unknown gate kind"};
}

uint64_t read_var_data(RawReader &rr)
{
	uint64_t value = 0;
	int bit_pos = 0;
	bool cont = 1;

	while(cont && rr)
	{
		if(bit_pos + 7 >= 64)
			throw std::runtime_error{"Extended header of type too long"};

		auto b = rr.read<uint8_t>();
		value |= (b & 0x7f) << bit_pos;
		bit_pos += 7;
		cont = b >> 7;
	}

	return value;
}


// Read type
//--------------------------------------------------------------------------
Type read_type(RawReader &rr)
{
	uint8_t header;
	rr >> header;

	uint8_t type_id = header & 0x3f;
	uint64_t length = read_var_data(rr);

	switch(type_id)
	{
		case 1: return IntegerType{true, (int)length};
		case 2: return IntegerType{false, (int)length};
		case 3: return ArrayType{read_type(rr), (int)length};
		case 4:
		{
			StructType strukt;
			for(uint8_t i = 0; i < length; ++i)
			{
				std::string name; rr >> name;
				strukt.members.push_back({name, std::unique_ptr<Type>{new Type{read_type(rr)}}});
			}

			return strukt;
		}
		case 5:
		{
			if(length != 1)
				throw std::runtime_error{"The bit-width of a boolean must be one"};

			return BoolType{};
		}
		default:
			throw std::runtime_error{"Unknown type: " + std::to_string(type_id)};
	}
}


struct InputPartitioning
{
	enum Kind { atomic = 0, array = 1, strukt = 2 };

	Kind kind;
	uint32_t size;
	std::vector<std::unique_ptr<InputPartitioning>> children;
};

std::unique_ptr<InputPartitioning> read_input_partitioning(RawReader &rr)
{
	std::unique_ptr<InputPartitioning> ip{new InputPartitioning};

	auto partitioning = rr.read<uint8_t>();
	ip->kind = InputPartitioning::Kind(partitioning >> 6);
	ip->size = partitioning & 0x3f;

	// Handle extended header
    if(ip->size == 0)
      ip->size = read_var_data(rr);

	switch(ip->kind)
	{
		case InputPartitioning::atomic:
			// Nothing to do
		break;

		case InputPartitioning::array:
		{
			ip->children.push_back(read_input_partitioning(rr));
		} break;

		case InputPartitioning::strukt:
		{
			ip->children.reserve(ip->size);
			for(uint32_t i = 0; i < ip->size; ++i)
				ip->children.push_back(read_input_partitioning(rr));
		} break;

		default:
			throw std::runtime_error{"Invalid input partitioning"};
	}

	return ip;
}

}


//==================================================================================================
void create_inputs_from_partitioning(InputPartitioning const *ip, Circuit &circuit)
{
	switch(ip->kind)
	{
		case InputPartitioning::Kind::atomic:
		{
			Input input;
			input.party = Party::alice; // Just temporary. We will later assign the real party
			input.width = ip->size;
			circuit.inputs.push_back(input);
		} break;

		case InputPartitioning::Kind::array:
		{
			for(uint32_t i = 0; i < ip->size; ++i)
				create_inputs_from_partitioning(ip->children[0].get(), circuit);
		} break;

		case InputPartitioning::Kind::strukt:
		{
			for(uint32_t i = 0; i < ip->size; ++i)
				create_inputs_from_partitioning(ip->children[i].get(), circuit);
		} break;
	}
}

void assign_input_gates_to_variables(Circuit &circuit)
{
	InputID cur_input{0};
	InputID max_input{circuit.inputs.size() - 1};
	for(auto *var: circuit.ordered_inputs)
	{
		int width = get_bit_width(var->type);
		while(cur_input <= max_input && width > 0)
		{
			var->inputs.push_back(cur_input);
			width -= circuit.get_width(cur_input);
			circuit.inputs[cur_input.value].party = var->party;
			cur_input.value++;
		}

		if(width != 0)
			throw std::runtime_error{"Invalid input partitioning"};
	}

	for(auto &call: circuit.function_calls)
	{
		for(auto &ret: call.returns)
		{
			int width = get_bit_width(ret.type);
			while(cur_input <= max_input && width > 0)
			{
				ret.inputs.push_back(cur_input);
				width -= circuit.get_width(cur_input);
				circuit.inputs[cur_input.value].party = Party::alice;
				cur_input.value++;
			}

			if(width != 0)
				throw std::runtime_error{"Invalid input partitioning"};
		}
	}
}

Circuit read_cbmc_circuit(std::string const &path)
{
	std::ifstream circuit_file{path};
	if(!circuit_file)
		throw std::runtime_error{"Opening file failed: " + path};

	RawReader rr{circuit_file};

	auto magic = rr.read<uint32_t>();
	if(magic != 0xCB11C06C)
		throw std::runtime_error{"It's not a circuit file"};

	uint8_t const supported_version = 0x5;
	auto version = rr.read<uint8_t>();
	if(version != supported_version)
	{
		throw std::runtime_error{
			"Unsupported file version: " + std::to_string(version) + " (only version "
			+ std::to_string(supported_version) + " is supported)"
		};
	}

	uint32_t num_gates, num_inputs, num_outputs, num_input_vars, num_output_vars, num_function_calls;
	rr >> num_gates >> num_inputs >> num_outputs >> num_input_vars >> num_output_vars >> num_function_calls;

	std::string name;
	rr >> name;

	std::cout << name << ": " << num_gates << " gates, " << num_inputs << " inputs, " << num_outputs << " outputs, "
	          << num_input_vars << " input vars, " << num_output_vars << " output vars, "
	          << num_function_calls << " external calls" << std::endl;


	// Read properties
	while(true)
	{
		auto prop_name = rr.read<std::string>();
		if(prop_name.empty())
			break;

		auto type = read_type(rr);
		std::cout << "PROP " << prop_name << " : " << type << " = ";
		if(type.kind() == TypeKind::integer)
		{
			if(type.integer().is_signed && type.integer().width == 32)
				std::cout << rr.read<int32_t>();
			else
				std::cout << " <unsupported integer type: only int32_t is supported right now>";
		}
		else
			std::cout << " <unsupported type>";

		std::cout << std::endl;
	}

	Circuit circuit;
	circuit.gates.resize(num_gates);
	circuit.inputs.reserve(num_inputs);
	circuit.outputs.reserve(num_outputs);

	IDConverter id_converter{&circuit, num_inputs, num_gates};

	// Read circuit input variables
	for(uint32_t i = 0; i < num_input_vars; ++i)
	{
		auto name = rr.read<std::string>();
		auto party = (Party)rr.read<uint8_t>();
		auto type = read_type(rr);

		circuit.add_input_variable(party, name, {}, type);
	}

	// Read circuit output variables
	for(uint32_t i = 0; i < num_output_vars; ++i)
	{
		auto name = rr.read<std::string>();
		auto type = read_type(rr);

		circuit.add_output_variable(name, {}, type);
	}

	// Read function calls
	for(uint32_t i = 0; i < num_function_calls; ++i)
	{
		Circuit::FunctionCall call;
		uint32_t num_args, num_returns;
		rr >> call.name >> num_args >> num_returns;

		// Read function returns (which are inputs to our circuit)
		for(uint32_t r = 0; r < num_returns; ++r)
		{
			Circuit::FunctionCall::Return ret;
			ret.name = rr.read<std::string>();
			ret.type = read_type(rr);

			call.returns.push_back(std::move(ret));
		}

		// Read function arguments (which are outputs from our circuit)
		for(uint32_t a = 0; a < num_args; ++a)
		{
			Circuit::FunctionCall::Arg arg;
			arg.name = rr.read<std::string>();
			arg.type = read_type(rr);

			call.args.push_back(std::move(arg));
		}

		circuit.function_calls.push_back(std::move(call));
	}

	// Read the widths of our INPUT gates
	auto input_partitioning = read_input_partitioning(rr);
	create_inputs_from_partitioning(input_partitioning.get(), circuit);
	assign_input_gates_to_variables(circuit);

	// Read gates
	uint32_t file_gate_id = 0;
	for(uint32_t i = 0; i < num_gates; ++i)
	{
		GateID gate_id{i};
		auto kind_pair = read_gate_kind(rr);
		switch(kind_pair.first)
		{
			case GateKind::and_gate:
			case GateKind::or_gate:
			case GateKind::xor_gate:
			case GateKind::add_gate:
			case GateKind::sub_gate:
			case GateKind::mul_gate:
			{
				uint32_t fanin0, fanin1;
				rr >> fanin0 >> fanin1;

				uint8_t width = circuit.get_width(id_converter.get(fanin0).id);
				assert(width);
				circuit.gates[gate_id.value] = Gate{kind_pair.first, 2, width};

				circuit.add_wire(id_converter.get(fanin0), {gate_id, 0});
				circuit.add_wire(id_converter.get(fanin1), {gate_id, 1});
				id_converter.set(file_gate_id++, primary_endpoint(gate_id));
			} break;

			case GateKind::not_gate:
			case GateKind::neg_gate:
			{
				uint32_t fanin;
				rr >> fanin;

				uint8_t width = circuit.get_width(id_converter.get(fanin).id);
				assert(width);
				circuit.gates[gate_id.value] = Gate{kind_pair.first, 1, width};

				circuit.add_wire(id_converter.get(fanin), {gate_id, 0});
				id_converter.set(file_gate_id++, primary_endpoint(gate_id));
			} break;

            case GateKind::one_gate:
            {
				circuit.gates[gate_id.value] = Gate{kind_pair.first, 0, 1};
                circuit.zero_fanin_elements.push_back(gate_id);
				id_converter.set(file_gate_id++, primary_endpoint(gate_id));
            } break;

            case GateKind::const_gate:
            {
				uint8_t width = read_var_data(rr);
				assert(width);
				uint64_t value = read_var_data(rr);
				circuit.gates[gate_id.value] = Gate{kind_pair.first, 0, width, value};
                circuit.zero_fanin_elements.push_back(gate_id);
				id_converter.set(file_gate_id++, primary_endpoint(gate_id));
            } break;

			case GateKind::combine_gate:
			{
				uint8_t num_fanins = kind_pair.second;
				uint8_t width = kind_pair.second;
				assert(width);
				circuit.gates[gate_id.value] = Gate{kind_pair.first, num_fanins, width};

				for(uint8_t k = 0; k < num_fanins; ++k)
				{
					WireEndpoint fanin = id_converter.get(rr.read<uint32_t>());
					circuit.add_wire(fanin, {gate_id, k});
				}

				id_converter.set(file_gate_id++, primary_endpoint(gate_id));
			} break;

			case GateKind::split_gate:
			{
				uint32_t fanin;
				rr >> fanin;
				WireEndpoint fanin_enpoint = id_converter.get(fanin);

				circuit.gates[gate_id.value] = Gate{kind_pair.first, 1, 1};
				circuit.add_wire(fanin_enpoint, {gate_id, 0});

				uint8_t num_fanouts = circuit.get_width(fanin_enpoint.id);
				id_converter.reserve_split_ids(num_fanouts);
				for(uint8_t i = 0; i < num_fanouts; ++i)
					id_converter.set(file_gate_id++, {gate_id, i});
			} break;
		}
	}

	// Read OUTPUT gates
	for(auto *var: circuit.ordered_outputs)
	{
		int width = get_bit_width(var->type);
		while(width > 0)
		{
			auto fanin = id_converter.get(rr.read<uint32_t>());
			circuit.outputs.push_back(fanin);
			OutputID oid{circuit.outputs.size() - 1};

			var->outputs.push_back(oid);
			width -= circuit.get_width(oid);
		}

		assert(width == 0);
	}

	// Read function argument OUTPUT gates
	for(auto &call: circuit.function_calls)
	{
		for(auto &arg: call.args)
		{
			int width = get_bit_width(arg.type);
			while(width > 0)
			{
				auto fanin = id_converter.get(rr.read<uint32_t>());
				circuit.outputs.push_back(fanin);
				OutputID oid{circuit.outputs.size() - 1};

				arg.outputs.push_back(oid);
				width -= circuit.get_width(oid);
			}

			assert(width == 0);
		}
	}

	return circuit;
}

}

