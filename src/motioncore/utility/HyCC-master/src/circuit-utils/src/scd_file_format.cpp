#include <circuit-utils/circuit_io.hpp>


namespace circ {

//==================================================================================================
namespace {

template<typename T>
struct RawBE
{
	explicit RawBE(T const &v) :
		val{v} {}

	T val;
};

template<typename T>
std::ostream& operator << (std::ostream &os, RawBE<T> val)
{
	// Convert to big endian
	char *begin = reinterpret_cast<char*>(&val.val);
	char *end = reinterpret_cast<char*>(&val.val) + sizeof(T);
	std::reverse(begin, end);

	return os.write(begin, sizeof(T));
}

using RawByteBE = RawBE<uint8_t>;
using RawByte2BE = RawBE<uint16_t>;
using Raw4ByteBE = RawBE<uint32_t>;
using Raw8ByteBE = RawBE<uint64_t>;


struct MsgPackUInt
{
	explicit MsgPackUInt(uint64_t const &v) :
		val{v} {}

	 uint64_t val;
};

// Writes an unsigned integer according to the msgpack specification.
std::ostream& operator << (std::ostream &os, MsgPackUInt val)
{
	if(val.val <= 127)
		return os << RawByteBE(val.val);
	else if(val.val <= 255)
		return os << RawByteBE{0xcc} << RawByteBE(val.val);
	else if(val.val <= 0xffff)
		return os << RawByteBE{0xcd} << RawByte2BE(val.val);
	else if(val.val <= 0xffffffff)
		return os << RawByteBE{0xce} << Raw4ByteBE(val.val);
	else
		return os << RawByteBE{0xcf} << Raw8ByteBE(val.val);
}


uint8_t convert_gate_kind(GateKind kind)
{
	switch(kind)
	{
		case GateKind::not_gate: return 0b0011;
		case GateKind::and_gate: return 0b1000;
		case GateKind::or_gate: return 0b1110;
		case GateKind::xor_gate: return 0b0110;
		case GateKind::one_gate: return 0b1111;

		case GateKind::add_gate:
		case GateKind::sub_gate:
		case GateKind::neg_gate:
		case GateKind::mul_gate:
		case GateKind::const_gate:
		case GateKind::combine_gate:
		case GateKind::split_gate:
			throw std::runtime_error{"SCD: unsupported gate kind"};
	}
}

class IDToWireConverter
{
public:
	IDToWireConverter(Circuit const &circuit) :
		m_circuit{circuit},
		m_num_inputs{circuit.inputs.size()}
	{
		// TODO Create a function to make a Circuit topologically sorted.

		m_sorted_gates.reserve(circuit.gates.size());
		m_gate_to_wire.resize(circuit.gates.size());
		topological_traversal(circuit, [&](ElementID id)
		{
			if(id.kind() == ElementID::Kind::gate)
			{
				// Plus one because the wire with the number circuit.inputs.size() is a dummy wire used
				// by unary gates to make them look like binary gates.
				m_gate_to_wire[id.id()] = m_sorted_gates.size() + m_num_inputs + 1;
				m_sorted_gates.push_back(id);
			}
		});
	}

	uint64_t operator () (ElementID id) const
	{
		switch(id.kind())
		{
			case ElementID::Kind::input: return id.id();
			case ElementID::Kind::gate: return m_gate_to_wire[id.id()];
			case ElementID::Kind::output:
			{
				ElementID fanin = m_circuit.outputs[id.id()].value().id;
				return (*this)(fanin);
			}
		}
	}

	std::vector<ElementID> const& sorted_gates() const { return m_sorted_gates; }
	uint64_t total_num_objects() const
	{
		return 3 + 3 * m_sorted_gates.size() + m_circuit.outputs.size();
	}

private:
	Circuit const &m_circuit;
	std::vector<ElementID> m_sorted_gates;
	std::vector<uint64_t> m_gate_to_wire;
	uint64_t m_num_inputs;
};

// SCD uses the msgpack specification. For simplicity, it puts everything into one large array.
void write_array_header(IDToWireConverter const &conv, std::ostream &file)
{
	uint64_t total_num_objects = conv.total_num_objects();
	if(total_num_objects <= 15)
		file << RawByteBE{uint8_t(0b1001'0000 | total_num_objects)};
	else if(total_num_objects <= 0xffff)
		file << RawByteBE{0xdc} << RawByte2BE(total_num_objects);
	else if(total_num_objects <= 0xffffffff)
		file << RawByteBE{0xdd} << Raw4ByteBE(total_num_objects);
	else
		throw std::runtime_error{"Too many gates for SCD file"};
}

void write_scd_circuit(Circuit const &circuit, std::ostream &file)
{
	IDToWireConverter id_to_wire{circuit};
	write_array_header(id_to_wire, file);

	file << MsgPackUInt{circuit.inputs.size()}
	     << MsgPackUInt{circuit.outputs.size()}
	     << MsgPackUInt{circuit.gates.size()};
	
	uint64_t dummy_wire = circuit.inputs.size();
	auto const &sorted_gates = id_to_wire.sorted_gates();

	for(uint64_t i = 0; i < sorted_gates.size(); ++i)
	{
		Gate const &gate = circuit[sorted_gates[i].as_gate_id()];
		uint64_t fanin = gate.fanins.size() ? id_to_wire(gate.fanins[0].id) : dummy_wire;
		file << MsgPackUInt{fanin};
	}

	for(uint64_t i = 0; i < sorted_gates.size(); ++i)
	{
		Gate const &gate = circuit[sorted_gates[i].as_gate_id()];
		assert(gate.num_fanins <= 2);

		if(gate.num_fanins < 2)
			file << MsgPackUInt{dummy_wire};
		else
			file << MsgPackUInt{id_to_wire(gate.fanins[1].id)};
	}

	for(uint64_t i = 0; i < sorted_gates.size(); ++i)
	{
		Gate const &gate = circuit[sorted_gates[i].as_gate_id()];
		file << MsgPackUInt{convert_gate_kind(gate.kind)};
	}

	for(auto const &opt_fanin: circuit.outputs)
		file << MsgPackUInt{id_to_wire(opt_fanin.value().id)};
}

}

void write_scd_circuit(Circuit const &circuit, std::string const &filepath)
{
	std::ofstream file{filepath};
	if(!file)
		throw std::runtime_error{"Opening file failed: " + filepath};

	write_scd_circuit(circuit, file);

	if(!file)
		throw std::runtime_error{"Writing file failed: " + filepath};
}

}
