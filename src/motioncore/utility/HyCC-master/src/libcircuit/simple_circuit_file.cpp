#include "simple_circuit.h"
#include "utils.h"

#include <memory>


//==================================================================================================
// *.circ File Format
//===================
//
// Header:
//   - num_gates: UInt32
//   - num_input_gates: UInt32
//   - num_output_gates: UInt32
//   - num_input_variables: UInt32
//   - num_output_variables: UInt32
//   - num_function_calls: UInt32
//   - name: String
//
// Properties:
//   - Prooperty[an empty name marks the end]:
//     - name: String
//     - type: Type
//     - value: (Depends on type)
//
// InputVariable[num_input_variables]:
//   - name: String
//   - owner: Owner
//   - type: Type
//
// OutputVariable[num_output_variables]:
//   - name: String
//   - type: Type
//
// FunctionCall[num_function_calls]:
//   - name: String
//   - num_args: UInt32
//   - num_returns: UInt32
//   - ReturnVariable[num_returns]:
//     - name: String
//     - type: Type
//   - ArgVariable[num_args]:
//     - name: String
//     - type: Type
//
// InputPartitioning
//
// Gate[num_gates]:
//   - operation: GateOp
//   - fanins: Fanin[]
//
// OutputVariableFanins[num_output_variables]:
//   - fanins: Fanin[]
//
// FunctionCallFanins[num_function_calls]:
//   - ArgVariable[num_args]:
//     - fanins: Fanin[]
//
// Data types
//===========
//
// String (variable length):
//   Null-terminated string of ASCII characters
// 
// Owner (8bit):
//   Describes the owner of a variable.
//   0: Input variable that belongs to Alice
//   1: Input variable that belongs to Bob
//
// GateOp (8bit):
//   Describes the gate operation (e.g. AND, OR, etc).
//
//   0x01: AND
//   0x02: OR
//   0x03: XOR
//   0x04: NOT
//   0x05: ONE
//
//   0xc1: ADD
//   0xc2: SUB
//   0xc3: NEG
//   0xc4: MUL
//   0xc5: CONST. The width is encoded in the following bytes and the value after that...
//
//   0b01xxxxxx: COMBINE, where xxxxxx is an unsigned number representing the number of fanins minus
//               one
//   0b10xxxxxx: COMBINE, where xxxxxx is an unsigned number representing the number of fanins minus
//               one. This is followed by more bytes...
//   0xe0: SPLIT
//
// Fanin (32bit unsigned):
//   Describes a single fanin to a gate. A fanin is the sum of the gate ID it is referring to and
//   the number of the output pin: Fanin = GateID + Pin. If GateID < num_input_gates, then GateID
//   refers to the GateID'nth input gate, otherwise GateID refers to gate Gate[GateID - num_input_gates].
//
// InputPartitioning (8bit):
//   Format: 0bxxwwwwww
//   xx:
//     0x0: Atomic. wwwwww contains the bit-width. If wwwwww is zero, width is in extended header.
//     0x1: Array. wwwwww contains the size. If wwwwww is zero, size is in extended header. Followed
//          by n InputPartitionings
//     0x2: Struct. wwwwww contains the number of elements. If wwwwww is zero, the number of
//          elements is in extended header. Followed by n InputPartitionings
//
// Type (variable length):
//   Specifies the data-type of input and output variables. It consists of at least a 8bit header
//   describing the type, optionally followed by more information.
//
//   The type header has the form 0bxxtttttt, where tttttt describes the type. xx should be ignored
//   for now.
//
//   Some types require the header to be extended by a couple of bytes. For those types, the
//   convention is that the first bit of each of the following bytes indicates whether another byte
//   follows (most-significant bit is 1) or not (MSB is 0).
//
//   ttttttt:
//     0x1: Signed integer. The bit-width is encoded in the extended header.
//     0x2: Unsigned integer. The bit-width is encoded in the extended header.
//     0x3: Array. The length is encoded in the extended header, followed by the element type.
//     0x4: Struct. The number of attributes `n` is encoded in the extended header, followed by
//          `n` pairs of (String,Type).
//


namespace {

//==================================================================================================
std::ostream& operator << (std::ostream &os, simple_circuitt::gatet::wire_endpointt ep)
{
	return os << RawUInt32{ep.gate->get_label() + ep.pin};
}

RawUInt8 convert_op(simple_circuitt::GATE_OP op, uint8_t extra = 0)
{
	assert(extra < 64);

	switch(op)
	{
		case simple_circuitt::AND: return RawUInt8{0x01};
		case simple_circuitt::OR: return RawUInt8{0x02};
		case simple_circuitt::XOR: return RawUInt8{0x03};
		case simple_circuitt::NOT: return RawUInt8{0x04};
		case simple_circuitt::ONE: return RawUInt8{0x05};

		case simple_circuitt::ADD: return RawUInt8{0xc1};
		case simple_circuitt::SUB: return RawUInt8{0xc2};
		case simple_circuitt::NEG: return RawUInt8{0xc3};
		case simple_circuitt::MUL: return RawUInt8{0xc4};
		case simple_circuitt::CONST: return RawUInt8{0xc5};

		case simple_circuitt::COMBINE: return RawUInt8{uint8_t(0x40 | extra)};
		case simple_circuitt::SPLIT: return RawUInt8{0xe0};

		default: assert(0);
	}
}

std::pair<int, int> count_variables(simple_circuitt const &circuit)
{
	int input_vars = 0, output_vars = 0;
	for(auto const &var: circuit.variables())
	{
		input_vars += var.owner != variable_ownert::output;
		output_vars += var.owner == variable_ownert::output;
	}

	return {input_vars, output_vars};
}


struct InputPartitioning
{
	enum Kind { atomic = 0, array = 1, strukt = 2 };

	Kind kind;
	uint32_t size;
	std::vector<std::unique_ptr<InputPartitioning>> children;
};

void write_var_data(std::ostream &os, uint64_t val)
{
	if(val == 0)
	{
		os << RawUInt8{0};
		return;
	}

	while(val)
	{
		uint8_t cur_data = val & 0x7f;
		val >>= 7;
		cur_data |= (val != 0) << 7;

		os << RawUInt8{(uint8_t)cur_data};
	}
}

using VectorGateRange = IteratorRange<std::vector<simple_circuitt::gatet*>::const_iterator>;
void write_input_partition_header(std::ostream &os, InputPartitioning::Kind kind, uint64_t size)
{
	// If size is zero we must use write_var_data() because zero is the indicator for an extended
	// header.
	if(size < 64 && size != 0)
      os << RawUInt8(((uint8_t)kind << 6) | size);
    else
    {
      os << RawUInt8((uint8_t)kind << 6);
      write_var_data(os, size);
    }
}

size_t write_input_partitioning(std::ostream &os, Type const &type, VectorGateRange &gates)
{
	assert(!gates.empty());

	switch(type.kind())
	{
		case TypeKind::bits:
		case TypeKind::boolean:
		case TypeKind::integer:
		{
			int width = get_bit_width(type);

			if(gates.front()->get_width() == width)
			{
				write_input_partition_header(os, InputPartitioning::atomic, width);
				++gates.b;
				return 1;
			}
			else
			{
				// We assume that all gates that make up an integer have the same width (usually 1)
				int gate_width = gates.front()->get_width();
				assert(width % gate_width == 0);

				int gate_count = width / gate_width;
				for(int i = 0; i < gate_count; ++i, ++gates.b)
				{
					assert(!gates.empty());
					if(gates.front()->get_width() != gate_width)
						throw std::runtime_error{"Primitive types must consist of gates of equal width"};
				}

				write_input_partition_header(os, InputPartitioning::array, gate_count);
				write_input_partition_header(os, InputPartitioning::atomic, gate_width);

				return gate_count;
			}
		}

		case TypeKind::array:
		{
			int length = type.array().length;
			if(length == 0)
				throw std::runtime_error{"Zero-length arrays not supported"};

			write_input_partition_header(os, InputPartitioning::array, length);

			auto gates_per_element = write_input_partitioning(os, *type.array().sub, gates);

			assert(gates_per_element * (length - 1) <= gates.size());
			gates.b += gates_per_element * (length - 1);

			return gates_per_element * length;
		}

		case TypeKind::structure:
		{
			write_input_partition_header(os, InputPartitioning::strukt, type.structure().members.size());

			size_t num_gates = 0;
			for(auto const &pair: type.structure().members)
				num_gates += write_input_partitioning(os, *pair.second, gates);

			return num_gates;
		}
	}
}


// Writing Type
//--------------------------------------------------------------------------
void write_type_header(std::ostream &os, uint8_t type, uint64_t length)
{
	assert(type < 15);

	os << RawUInt8(type);
	write_var_data(os, length);
}

void write_type(std::ostream &os, Type const &type)
{
	switch(type.kind())
	{
		case TypeKind::bits:
			write_type_header(os, 1, type.bits().width);
			break;
		case TypeKind::boolean:
			write_type_header(os, 5, 1);
			break;
		case TypeKind::integer:
			write_type_header(os, type.integer().is_signed ? 1 : 2, type.integer().width);
			break;
		case TypeKind::array:
		{
			write_type_header(os, 3, type.array().length);
			write_type(os, *type.array().sub);
		} break;
		case TypeKind::structure:
		{
			write_type_header(os, 4, type.structure().members.size());
			for(auto const &pair: type.structure().members)
			{
				os << RawString{&pair.first};
				write_type(os, *pair.second);
			}
		}
	}
}

struct RawType { Type const *type; };
std::ostream& operator << (std::ostream &os, RawType const &type)
{
	write_type(os, *type.type);
	return os;
}

}


//==================================================================================================
void simple_circuitt::write(std::ostream &os)
{
	// Magic number
	os << RawUInt32{0xCB11C06C};

	// Version
	os << RawUInt8{0x05};

	unsigned counter = 0;
	bool one_gate_is_used = ONE_GATE->fanouts.size() > 1; // The one gate always has a fanout to the zero gate

	uint32_t num_gates = gates_SIZE;
	if(ZERO_GATE->fanouts.size() > 0)
		num_gates += 2; // If the zero gate is used than the one gate is also used
	else if(one_gate_is_used)
		num_gates += 1;

	os << RawUInt32{num_gates} << RawUInt32{input_gates_SIZE} << RawUInt32{output_gates_SIZE};

	auto num_vars = count_variables(*this);
	os << RawUInt32(num_vars.first) << RawUInt32(num_vars.second) << RawUInt32(m_function_calls.size());

	os << RawString{&m_name};

	// Write properties
	os << RawCString{""}; // End-of-properties marker

	// Circuit-level input variables and input variables from function calls
	int total_num_input_variables = m_ordered_inputs.size();

	// Write circuit input variables
	for(auto var: m_ordered_inputs)
	{
		for(auto gate: var->gates)
			gate->gate_label = counter++;

		uint8_t party = var->owner == variable_ownert::input_alice ? 0 : 1;
		os << RawString{&var->name} << RawUInt8{party} << RawType{&var->type};
	}

	// Write circuit output variables
	for(auto const &pair: m_variables)
	{
		auto const &var = pair.second;
		if(var.owner == variable_ownert::output)
			os << RawString{&var.name} << RawType{&var.type};
	}

	// Write variables used by function calls
	for(auto const &call: m_function_calls)
	{
		os << RawString{&call.name} << RawUInt32(call.args.size()) << RawUInt32(call.returns.size());

		for(auto const &ret: call.returns)
		{
			for(auto gate: ret.gates)
				gate->gate_label = counter++;

			os << RawString{&ret.name} << RawType{&ret.type};
			total_num_input_variables++;
		}

		for(auto const &arg: call.args)
			os << RawString{&arg.name} << RawType{&arg.type};
	}

	// Write the widths of our INPUT gates
	write_input_partition_header(os, InputPartitioning::strukt, total_num_input_variables);
	for(auto var: m_ordered_inputs)
	{
		VectorGateRange gates{var->gates.begin(), var->gates.end()};
		write_input_partitioning(os, var->type, gates);
	}
	for(auto const &call: m_function_calls)
	{
		for(auto const &ret: call.returns)
		{
			VectorGateRange gates{ret.gates.begin(), ret.gates.end()};
			write_input_partitioning(os, ret.type, gates);
		}
	}

	// Write gates
	topological_traversal([&](gatet *gate)
	{
		switch(gate->operation)
		{
			// Binary ops
			case AND:
			case OR:
			case XOR:
			case ADD:
			case SUB:
			case MUL:
				gate->gate_label = counter++;
				os << convert_op(gate->operation) << gate->fanins[0] << gate->fanins[1];
			break;

			// Unary ops
			case NOT:
			case NEG:
				gate->gate_label = counter++;
				os << convert_op(gate->operation) << gate->fanins[0];
			break;

			case CONST:
				gate->gate_label = counter++;
				os << convert_op(gate->operation);
				write_var_data(os, gate->width);
				write_var_data(os, gate->value);
			break;

			case COMBINE:
				assert(gate->fanins.size() <= 64);
				gate->gate_label = counter++;
				os << convert_op(COMBINE, gate->fanins.size() - 1);
				for(auto fanin: gate->fanins)
					os << fanin;
			break;

			case SPLIT:
				assert(gate->fanouts.size());

				gate->gate_label = counter;
				os << convert_op(SPLIT) << gate->fanins[0];

				// Each bit of the input gets its own ID
				counter += gate->fanins[0].gate->get_width();
			break;

			case ONE:
				gate->gate_label = counter++;
				os << convert_op(gate->operation);
			break;

			case OUTPUT:
			case INPUT:
				// Nothing to do
			break;

			case LUT:
				throw std::runtime_error{"LUT export not implemented yet"};
			break;
		}
	});

	// Write OUTPUT gates
	for(auto &pair: m_variables)
	{
		variablet &var = pair.second;
		if(var.owner == variable_ownert::output)
		{
			for(auto gate: var.gates)
				os << gate->fanins[0];
		}
	}

	// Write function argument OUTPUT gates
	for(auto const &call: m_function_calls)
	{
		for(auto const &arg: call.args)
		{
			for(auto gate: arg.gates)
				os << gate->fanins[0];
		}
	}
}


//==================================================================================================
using wire_endpointt = simple_circuitt::gatet::wire_endpointt;

class IDConverter
{
public:
	explicit IDConverter(simple_circuitt *circuit, uint32_t num_inputs, uint32_t num_gates) :
		m_circuit{circuit},
		// `num_gates` is only an estimate of the total number of IDs because SPLIT gates require
		// more than one ID.
		m_id_to_endpoint(num_inputs + num_gates),
		m_cur_id{0}
	{
		for(auto &in: circuit->inputs())
			m_id_to_endpoint[m_cur_id++] = primary_output(&in);
	}

	wire_endpointt get(uint32_t id) const
	{
		assert(id < m_id_to_endpoint.size());
		return m_id_to_endpoint[id];
	}

	void add(wire_endpointt ep)
	{
		assert(m_cur_id < m_id_to_endpoint.size());
		m_id_to_endpoint[m_cur_id++] = ep;
	}

	void reserve_split_ids(uint32_t count)
	{
		m_id_to_endpoint.resize(m_id_to_endpoint.size() + count - 1);
	}

	simple_circuitt* circuit() { return m_circuit; }

private:
	simple_circuitt *m_circuit;
	std::vector<wire_endpointt> m_id_to_endpoint;
	uint32_t m_cur_id;
};


variable_ownert to_owner(uint8_t party)
{
	switch(party)
	{
		case 0: return variable_ownert::input_alice; // Inputs from function calls are assigned to Alice
		case 1: return variable_ownert::input_alice;
		case 2: return variable_ownert::input_bob;
		default: throw std::runtime_error{"Unsupported party: " + std::to_string(party)};
	}
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

std::pair<simple_circuitt::GATE_OP, uint8_t> read_gate_kind(RawReader &rr)
{
	uint8_t data;
	rr >> data;

	if((data & 0xe0) == 0) // Boolean gate
	{
		switch(data & 0x7)
		{
			case 1: return {simple_circuitt::AND, 0};
			case 2: return {simple_circuitt::OR, 0};
			case 3: return {simple_circuitt::XOR, 0};
			case 4: return {simple_circuitt::NOT, 0};
			case 5: return {simple_circuitt::ONE, 0};
			default:
				throw std::runtime_error{"Unknown boolean gate"};
		}
	}
	else if((data & 0xe0) == 0xc0) // Arithmetic gate
	{
		switch(data & 0x7)
		{
			case 1: return {simple_circuitt::ADD, 0};
			case 2: return {simple_circuitt::SUB, 0};
			case 3: return {simple_circuitt::NEG, 0};
			case 4: return {simple_circuitt::MUL, 0};
			case 5: return {simple_circuitt::CONST, 0};
			default:
				throw std::runtime_error{"Unknown arithmetic gate"};
		}
	}
	else if((data & 0xc0) == 0x40) // Combine gate
		return {simple_circuitt::COMBINE, (data & 0x3f) + 1};
	else if((data & 0xe0) == 0xe0) // Split gate
		return {simple_circuitt::SPLIT, data & 0x2f};
	else
		throw std::runtime_error{"Unknown gate kind"};
}


//------------------------------------------------------------------------------
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
			for(uint64_t i = 0; i < length; ++i)
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

RawReader& operator >> (RawReader &rr, Type &type)
{
	type = read_type(rr);
	return rr;
}


//------------------------------------------------------------------------------
void create_inputs_from_partitioning(InputPartitioning const *ip, simple_circuitt &circuit)
{
	switch(ip->kind)
	{
		case InputPartitioning::Kind::atomic:
		{
			circuit.create_input_gate("", ip->size);
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

void assign_input_gates_to_variables(simple_circuitt &circuit)
{
	auto inputs = circuit.inputs();

	for(auto *var: circuit.ordered_inputs())
	{
		int width = get_bit_width(var->type);
		while(!inputs.empty() && width > 0)
		{
			var->gates.push_back(&inputs.front());
			width -= inputs.front().get_width();
			++inputs.b;
		}

		if(width != 0)
			throw std::runtime_error{"Invalid input partitioning"};
	}

	for(auto &call: circuit.function_calls())
	{
		for(auto &ret: call.returns)
		{
			int width = get_bit_width(ret.type);
			while(!inputs.empty() && width > 0)
			{
				ret.gates.push_back(&inputs.front());
				width -= inputs.front().get_width();
				++inputs.b;
			}

			if(width != 0)
				throw std::runtime_error{"Invalid input partitioning"};
		}
	}
}

void simple_circuitt::read(std::istream &is)
{
	RawReader rr{is};

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

	rr >> m_name;

	m_logger->debug() << num_gates << " gates, " << num_inputs << " inputs, " << num_outputs << " outputs, "
	          << num_input_vars << " input vars, " << num_output_vars << " output vars, "
	          << num_function_calls << " external calls" << eom;

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

	// Read circuit input variables
	for(uint32_t i = 0; i < num_input_vars; ++i)
	{
		auto name = rr.read<std::string>();
		auto owner = (variable_ownert)rr.read<uint8_t>();
		auto type = read_type(rr);

		add_variable(name, owner, type, {});
	}

	// Read circuit output variables
	for(uint32_t i = 0; i < num_output_vars; ++i)
	{
		auto name = rr.read<std::string>();
		auto type = read_type(rr);

		add_variable(name, variable_ownert::output, type, {});
	}

	// Read variables used by function calls
	for(uint32_t i = 0; i < num_function_calls; ++i)
	{
		function_callt call;
		call.call_id = i;
		uint32_t num_args, num_returns;
		rr >> call.name >> num_args >> num_returns;

		for(uint32_t r = 0; r < num_returns; ++r)
		{
			function_callt::vart ret;
			rr >> ret.name >> ret.type;
			call.returns.push_back(std::move(ret));
		}

		for(uint32_t r = 0; r < num_args; ++r)
		{
			function_callt::vart arg;
			rr >> arg.name >> arg.type;
			call.args.push_back(std::move(arg));
		}

		add_function_call(std::move(call));
	}

	// Read the widths of our INPUT gates
	auto input_partitioning = read_input_partitioning(rr);
	create_inputs_from_partitioning(input_partitioning.get(), *this);
	assign_input_gates_to_variables(*this);

	// Read gates
	IDConverter id_converter{this, num_inputs, num_gates};
	for(uint32_t gate_id = 0; gate_id < num_gates; ++gate_id)
	{
		auto kind_pair = read_gate_kind(rr);
		switch(kind_pair.first)
		{
			case AND:
			case OR:
			case XOR:
			case ADD:
			case SUB:
			case MUL:
			{
				uint32_t fanin0, fanin1;
				rr >> fanin0 >> fanin1;

				uint8_t width = id_converter.get(fanin0).gate->get_width();
				assert(width);
				auto gate = get_or_create_gate(kind_pair.first, width);

				gate->add_fanin(id_converter.get(fanin0), 0);
				gate->add_fanin(id_converter.get(fanin1), 1);

				id_converter.add(primary_output(gate));
			} break;

			case NOT:
			case NEG:
			{
				uint32_t fanin;
				rr >> fanin;

				// Is this the ZERO_GATE?
				if(kind_pair.first == NOT && id_converter.get(fanin).gate == ONE_GATE)
					id_converter.add(primary_output(ZERO_GATE));
				else
				{
					uint8_t width = id_converter.get(fanin).gate->get_width();
					assert(width);
					auto gate = get_or_create_gate(kind_pair.first, width);

					gate->add_fanin(id_converter.get(fanin), 0);
					id_converter.add(primary_output(gate));
				}
			} break;

            case ONE:
            {
				id_converter.add(primary_output(ONE_GATE));
            } break;

            case CONST:
            {
				uint8_t width = read_var_data(rr);
				assert(width);
				uint64_t value = read_var_data(rr);
				auto gate = get_or_create_gate(kind_pair.first, width, value);
				id_converter.add(primary_output(gate));
            } break;

			case COMBINE:
			{
				uint8_t num_fanins = kind_pair.second;
				assert(num_fanins);
				auto gate = get_or_create_gate(kind_pair.first, num_fanins);

				for(uint8_t k = 0; k < num_fanins; ++k)
					gate->add_fanin(id_converter.get(rr.read<uint32_t>()), k);

				id_converter.add(primary_output(gate));
			} break;

			case SPLIT:
			{
				uint32_t fanin;
				rr >> fanin;

				uint8_t num_fanouts = id_converter.get(fanin).gate->get_width();
				auto gate = get_or_create_gate(kind_pair.first, num_fanouts);

				wire_endpointt fanin_endpoint = id_converter.get(fanin);
				gate->add_fanin(fanin_endpoint, 0);

				id_converter.reserve_split_ids(num_fanouts);
				for(uint8_t i = 0; i < num_fanouts; ++i)
					id_converter.add({gate, i});
			} break;

			case INPUT:
			case OUTPUT:
			case LUT:
				throw std::runtime_error{"Unexpected gate kind"};
		}
	}

	// Read OUTPUT gates
	for(auto *var: m_ordered_outputs)
	{
		int width = get_bit_width(var->type);
		while(width > 0)
		{
			auto fanin = id_converter.get(rr.read<uint32_t>());
			auto gate = create_output_gate("", fanin.gate->get_width());
			gate->add_fanin(fanin, 0);

			var->gates.push_back(gate);
			width -= gate->get_width();
		}

		assert(width == 0);
	}

	// Read function argument OUTPUT gates
	for(auto &call: m_function_calls)
	{
		for(auto &arg: call.args)
		{
			int width = get_bit_width(arg.type);
			while(width > 0)
			{
				auto fanin = id_converter.get(rr.read<uint32_t>());
				auto gate = create_output_gate("", fanin.gate->get_width());
				gate->add_fanin(fanin, 0);

				arg.gates.push_back(gate);
				width -= gate->get_width();
			}

			assert(width == 0);
		}
	}
}
