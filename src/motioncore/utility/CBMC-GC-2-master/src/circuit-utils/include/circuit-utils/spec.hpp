#pragma once

#include "utility.hpp"

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <ostream>
#include <sstream>
#include <bitset>

#include <iostream>


namespace circ {


// Types
//==================================================================================================
// TODO Just use a damn class hierarchy to represent types!

struct BitsType
{
	int width;
};

struct IntegerType
{
	bool is_signed;
	int width;
};

struct ArrayType
{
	ArrayType(ArrayType&&) = default;
	ArrayType(struct Type *s, int l) :
		sub{s},
		length{l} {}

	ArrayType(ArrayType const&);
	ArrayType& operator = (ArrayType &&rhs) = default;
	ArrayType& operator = (ArrayType const &rhs);

	std::unique_ptr<struct Type> sub;
	int length;
};

struct StructType
{
	StructType() = default;
	StructType(StructType&&) = default;
	StructType(StructType const&);
	StructType& operator = (StructType &&rhs) = default;
	StructType& operator = (StructType const &rhs);

	std::vector<std::pair<std::string, std::unique_ptr<struct Type>>> members;
};

enum class TypeKind
{
	bits,
	integer,
	array,
	structure,
};

struct Type
{
	Type() :
		Type{BitsType{0}} {}

	Type(BitsType t) :
		m_kind{TypeKind::bits},
		m_bits{t} {}

	Type(IntegerType t) :
		m_kind{TypeKind::integer},
		m_integer{t} {}

	Type(ArrayType t) :
		m_kind{TypeKind::array},
		m_array{std::move(t)} {}

	Type(StructType t) :
		m_kind{TypeKind::structure},
		m_struct{std::move(t)} {}

	Type(Type const &rhs)
	{
		copy_from(rhs);
	}

	Type(Type &&rhs)
	{
		move_from(std::move(rhs));
	}

	Type& operator = (Type const &rhs)
	{
		if(this != &rhs)
		{
			destroy();
			copy_from(rhs);
		}

		return *this;
	}

	Type& operator = (Type &&rhs)
	{
		if(this != &rhs)
		{
			destroy();
			move_from(std::move(rhs));
		}

		return *this;
	}

	~Type() { destroy(); }

	TypeKind kind() const { return m_kind; }

	BitsType const& bits() const { assert(m_kind == TypeKind::bits); return m_bits; }
	IntegerType const& integer() const { assert(m_kind == TypeKind::integer); return m_integer; }
	ArrayType const& array() const { assert(m_kind == TypeKind::array); return m_array; }
	StructType const& structure() const { assert(m_kind == TypeKind::structure); return m_struct; }
	BitsType & bits() { assert(m_kind == TypeKind::bits); return m_bits; }
	IntegerType& integer() { assert(m_kind == TypeKind::integer); return m_integer; }
	ArrayType& array() { assert(m_kind == TypeKind::array); return m_array; }
	StructType& structure() { assert(m_kind == TypeKind::structure); return m_struct; }

private:
	TypeKind m_kind;
	union
	{
		BitsType m_bits;
		IntegerType m_integer;
		ArrayType m_array;
		StructType m_struct;
	};

private:
	void destroy()
	{
		switch(m_kind)
		{
			case TypeKind::bits: break;
			case TypeKind::integer: break;
			case TypeKind::array: m_array.~ArrayType(); break;
			case TypeKind::structure: m_struct.~StructType(); break;
		}
	}

	void copy_from(Type const &rhs)
	{
		m_kind = rhs.m_kind;
		switch(m_kind)
		{
			case TypeKind::bits: new (&m_bits) BitsType{rhs.m_bits}; break;
			case TypeKind::integer: new (&m_integer) IntegerType{rhs.m_integer}; break;
			case TypeKind::array: new (&m_array) ArrayType{rhs.m_array}; break;
			case TypeKind::structure: new (&m_struct) StructType{rhs.m_struct}; break;
		}
	}

	void move_from(Type &&rhs)
	{
		m_kind = rhs.m_kind;
		switch(m_kind)
		{
			case TypeKind::bits: new (&m_bits) BitsType{std::move(rhs.m_bits)}; break;
			case TypeKind::integer: new (&m_integer) IntegerType{std::move(rhs.m_integer)}; break;
			case TypeKind::array: new (&m_array) ArrayType{std::move(rhs.m_array)}; break;
			case TypeKind::structure: new (&m_struct) StructType{std::move(rhs.m_struct)}; break;
		}
	}
};

inline bool operator != (Type const &a, Type const &b);
inline bool operator == (Type const &a, Type const &b)
{
	if(a.kind() != b.kind())
		return false;

	switch(a.kind())
	{
		case TypeKind::bits:
			return a.bits().width == b.bits().width;
		case TypeKind::integer:
			return a.integer().width == b.integer().width && a.integer().is_signed == b.integer().is_signed;
		case TypeKind::array:
			return a.array().length == b.array().length && *a.array().sub == *b.array().sub;
		case TypeKind::structure:
		{
			auto size = a.structure().members.size();
			if(size != b.structure().members.size())
				return false;

			for(size_t i = 0; i < size; ++i)
			{
				auto const &mem_a = a.structure().members[i];
				auto const &mem_b = b.structure().members[i];
				if(mem_a.first != mem_b.first || *mem_a.second != *mem_b.second)
					return false;
			}

			return true;
		}
	}

	assert(0);
}

inline bool operator != (Type const &a, Type const &b)
{
	return !(a == b);
}


inline ArrayType::ArrayType(ArrayType const &rhs) :
	sub{new Type{*rhs.sub}},
	length{rhs.length} {}

inline ArrayType& ArrayType::operator = (ArrayType const &rhs)
{
	length = rhs.length;
	sub.reset(new Type{*rhs.sub});
	return *this;
}


inline StructType::StructType(StructType const &rhs)
{
	members.reserve(rhs.members.size());
	for(auto const &m: rhs.members)
		members.emplace_back(m.first, std::unique_ptr<Type>{new Type{*m.second}});
}

inline StructType& StructType::operator = (StructType const &rhs)
{
	members.clear();
	members.reserve(rhs.members.size());
	for(auto const &m: rhs.members)
		members.emplace_back(m.first, std::unique_ptr<Type>{new Type{*m.second}});

	return *this;
}


//==================================================================================================
inline StructType const* get_struct_type(Type const &t)
{
	if(t.kind() == TypeKind::structure)
		return &t.structure();

	return nullptr;
}

inline ArrayType const* get_array_type(Type const &t)
{
	if(t.kind() == TypeKind::array)
		return &t.array();

	return nullptr;
}

inline IntegerType const* get_integer_type(Type const &t)
{
	if(t.kind() == TypeKind::integer)
		return &t.integer();

	return nullptr;
}

inline BitsType const* get_bits_type(Type const &t)
{
	if(t.kind() == TypeKind::bits)
		return &t.bits();

	return nullptr;
}

inline Type const& get_leaf_type(Type const &t)
{
	switch(t.kind())
	{
		case TypeKind::bits: return t;
		case TypeKind::integer: return t;
		case TypeKind::array: return get_leaf_type(*t.array().sub);
		case TypeKind::structure: return t;
	}

	assert(0);
}

inline Type& get_leaf_type(Type &t)
{
	switch(t.kind())
	{
		case TypeKind::bits: return t;
		case TypeKind::integer: return t;
		case TypeKind::array: return get_leaf_type(*t.array().sub);
		case TypeKind::structure: return t;
	}

	assert(0);
}

inline bool array_sizes_equal(Type const &a, Type const &b)
{
	if(a.kind() != b.kind())
		return false;

	switch(a.kind())
	{
		case TypeKind::bits: return true;
		case TypeKind::integer: return true;
		case TypeKind::array:
			return a.array().length == b.array().length && array_sizes_equal(*a.array().sub, *b.array().sub);
		case TypeKind::structure: return a == b;
	}

	assert(0);
}

inline Type make_array_type(Type &&sub, int length)
{
	return Type{ArrayType{new Type{std::move(sub)}, length}};
}

inline int get_bit_width(Type const &t)
{
	switch(t.kind())
	{
		case TypeKind::bits: return t.bits().width;
		case TypeKind::integer: return t.integer().width;
		case TypeKind::array: return t.array().length * get_bit_width(*t.array().sub);
		case TypeKind::structure:
		{
			int width = 0;
			for(auto const &sub: t.structure().members)
				width += get_bit_width(*sub.second);

			return width;
		}
	}

	assert(0);
}

optional<IntegerType> common_int_type(IntegerType a, IntegerType b);
optional<Type> common_type(Type const &a, Type const &b);

template<typename Func>
void walk_type_with_path(Type const &type, std::string const &path, Func &&func)
{
	switch(type.kind())
	{
		case TypeKind::bits:
			func(path, type);
		break;

		case TypeKind::integer:
			func(path, type);
		break;

		case TypeKind::array:
		{
			auto arr_type = get_array_type(type);
			for(int i = 0; i < arr_type->length; ++i)
				walk_type_with_path(*arr_type->sub, path + '[' + std::to_string(i) + ']', std::forward<Func>(func));
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto const &m: struct_type->members)
				walk_type_with_path(*m.second, path + '.' + m.first, std::forward<Func>(func));
		} break;
	}
}


//------------------------------------------------------------------------------
std::ostream& operator << (std::ostream &os, Type const &t);
inline std::string to_str(Type const &t);

inline void type_to_string(Type const &t, std::string &out)
{
	switch(t.kind())
	{
		case TypeKind::bits:
		{
			out = "bits#" + std::to_string(t.bits().width) + out;
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
				struct_str += mem.first + ": " + to_str(*mem.second) + "; ";

			out = '{' + struct_str + '}' + out;
		} break;
	}
}

inline std::ostream& operator << (std::ostream &os, Type const &t)
{
	std::string str;
	type_to_string(t, str);
	return os << str;
}

inline std::string to_str(Type const &t)
{
	std::ostringstream os;
	os << t;
	return os.str();
}

//------------------------------------------------------------------------------
std::string to_c_decl(Type const &t, std::string const &name);

inline void to_c_decl_impl(Type const &t, std::string &out, optional<std::string> const &name)
{
	switch(t.kind())
	{
		case TypeKind::bits:
		{
			throw std::runtime_error{"Converting bits to C type no supported yet"};
		} break;

		case TypeKind::integer:
		{
			char const *type_name = t.integer().is_signed ? "int" : "uint";
			std::string s = type_name + std::to_string(t.integer().width) + "_t";
			if(name)
				s += ' ' + *name;
			out += s;
		} break;

		case TypeKind::array:
		{
			optional<std::string> sub_name;
			if(get_array_type(*t.array().sub))
				sub_name = name;
			else
				out += ' ' + *name;

			out += '[' + std::to_string(t.array().length) + ']';
			to_c_decl_impl(*t.array().sub, out, sub_name);
		} break;

		case TypeKind::structure:
		{
			std::string struct_str;
			for(auto const &mem: t.structure().members)
				struct_str += to_c_decl(*mem.second, mem.first) + "; ";

			std::string s = "struct {" + struct_str + '}';
			if(name)
				s += ' ' + *name;
			out += s;
		} break;
	}
}

inline std::string to_c_decl(Type const &t, std::string const &name)
{
	std::string str;
	to_c_decl_impl(t, str, name);
	return str;
}


// Values
//==================================================================================================
// The largest scalar type that CBMC-GC supports (I hope).
using UMaxScalar = uint64_t;
using MaxScalar = int64_t;

using RawValue = std::vector<uint8_t>;

// Large enough to store any number we care for.
struct Number
{
	bool is_neg; // Whether `value` should be interpreted as a negative number
	UMaxScalar value;
};

inline bool operator < (Number a, Number b)
{
	if(a.is_neg == b.is_neg)
		return a.value < b.value;
	else
		return a.is_neg;
}

inline bool operator == (Number a, Number b)
{
	return a.is_neg == b.is_neg && a.value == b.value;
}

inline bool operator > (Number a, Number b)
{
	return !(a < b || a == b);
}

inline bool operator <= (Number a, Number b)
{
	return !(b < a);
}

inline bool operator >= (Number a, Number b)
{
	return !(a < b);
}

IntegerType find_closest_type(Number n);

inline size_t get_num_bytes(Type const &t)
{
	// Round up.
	return (get_bit_width(t) + 7) / 8;
}

inline int get_num_elements(Type const &t)
{
	switch(t.kind())
	{
		case TypeKind::bits:
		case TypeKind::integer: return 1;
		case TypeKind::array: return t.array().length * get_num_elements(*t.array().sub);
		case TypeKind::structure: return 1;
	}

	assert(0);
}

inline Number num(UMaxScalar val, IntegerType t)
{
	if(t.is_signed)
		return {bool(val & (1ull << (t.width - 1))), val};
	else
		return {false, val};
}

inline std::string to_str(Number n)
{
	if(n.is_neg)
		return std::to_string((MaxScalar)n.value);

	return std::to_string(n.value);
}

inline std::ostream& operator << (std::ostream &os, Number n)
{
	return os << to_str(n);
}


struct TypedValue
{
	TypedValue() = default;
	TypedValue(TypedValue const&) = default;
	explicit TypedValue(Type &&t) :
		type{std::move(t)},
		value(get_num_bytes(type)) {}

	explicit TypedValue(Type const &t) :
		type{t},
		value(get_num_bytes(type)) {}

	explicit TypedValue(Type &&t, std::vector<uint8_t> &&val) :
		type{std::move(t)},
		value{std::move(val)}
	{
		assert(value.size() == get_num_bytes(type));
	}

	explicit TypedValue(Type const &t, std::vector<uint8_t> const &val) :
		type{t},
		value{val}
	{
		assert(value.size() == get_num_bytes(type));
	}

	Type type;
	std::vector<uint8_t> value;
};

inline bool operator == (TypedValue const &a, TypedValue const &b)
{
	return a.type == b.type && a.value == b.value;
}

inline void assign(TypedValue &val, std::vector<uint8_t> &&value)
{
	if(get_num_bytes(val.type) != value.size())
		throw std::runtime_error{"Type mismatch in assignment"};

	val.value = std::move(value);
}

inline Number get_element(IntegerType int_type, std::vector<uint8_t> const &data, int idx)
{
	assert(int_type.width <= 64);
	uint64_t val = extract_bits(data, int_type.width * idx, int_type.width);

	if(int_type.is_signed)
		val = sign_extend(val, int_type.width);

	bool is_neg = val & (1ull << (int_type.width - 1));
	return {is_neg, val};
}

// Returns true if `n` can be converted to `type` without loosing information.
bool is_representable(IntegerType type, Number n);

// Returns true if `val` can be converted to `t` without loosing information.
inline bool is_representable(Type const &t, TypedValue const &val)
{
	if(!array_sizes_equal(val.type, t))
		return false;

	auto dest_elem_type = get_leaf_type(t);
	auto src_elem_type = get_leaf_type(val.type);

	if(src_elem_type.kind() != dest_elem_type.kind())
		return false;

	if(src_elem_type.kind() == TypeKind::bits)
		return get_bit_width(src_elem_type) <= dest_elem_type.bits().width;

	if(src_elem_type.kind() == TypeKind::integer)
	{
		auto const num_elements = get_num_elements(val.type);
		for(int i = 0; i < num_elements; ++i)
		{
			Number num = get_element(src_elem_type.integer(), val.value, i);
			if(!is_representable(dest_elem_type.integer(), num))
				return false;
		}

		return true;
	}

	throw std::runtime_error{"is_representable(): structs not yet supported"};
}

inline void sign_extend(uint8_t *bytes, int byte_count, int sign_pos)
{
	assert(byte_count <= 8);
	assert(is_power_of_two(byte_count));
	assert(sign_pos < byte_count * 8);

	switch(byte_count)
	{
		case 1: *bytes = sign_extend(*bytes, sign_pos); break;
		case 2: *(uint16_t*)bytes = sign_extend(*(uint16_t*)bytes, sign_pos); break;
		case 4: *(uint32_t*)bytes = sign_extend(*(uint32_t*)bytes, sign_pos); break;
		case 8: *(uint64_t*)bytes = sign_extend(*(uint64_t*)bytes, sign_pos); break;
	}
}

template<typename Func>
void for_each_bit(TypedValue const &val, Func &&func)
{
	if(val.value.empty())
		return;

	auto bit_width = get_bit_width(val.type);
	auto num_complete_bytes = bit_width / 8;
	auto num_rest_bits = bit_width % 8;

	for(int i = 0; i < num_complete_bytes; ++i)
	{
		auto cur_byte = val.value[i];
		for(int k = 0; k < 8; ++k)
			func(i * 8 + k, (cur_byte >> k) & 1);
	}

	auto last_byte = val.value.back();
	for(int k = 0; k < num_rest_bits; ++k)
		func(num_complete_bytes * 8 + k, (last_byte >> k) & 1);
}

// Converts a value to a different type if
// - they have the same bit-width or
// - they have the same array dimensions .
//
// Valid:
// - int16[2] <-> int32
// - uint64 <-> int64
// - int8[5][5] <-> uint32[5][5]
// 
// Invalid:
// - int16[2] <-> int16
// - uint64 <-> uint32
// - int8[5][5] <-> int8[3][3]
//
// TODO Split function into convert_bits() and convert_value().
inline TypedValue convert(Type const &t, TypedValue const &val)
{
	auto dest_bit_width = get_bit_width(t);
	auto src_bit_width = get_bit_width(val.type);


	if(dest_bit_width == src_bit_width)
	{
		// Like reinterprest_cast. Nothing to do.
		return TypedValue{t, val.value};
	}

	if(array_sizes_equal(t, val.type))
	{
		auto src_elem_type = get_leaf_type(val.type);
		auto dest_elem_type = get_leaf_type(t);

		if(src_elem_type.kind() == TypeKind::structure || dest_elem_type.kind() == TypeKind::structure)
			throw std::runtime_error{"Cannot convert struct to type with different width"};

		auto src_elem_width = get_bit_width(src_elem_type);
		auto dest_elem_width = get_bit_width(dest_elem_type);

		assert(src_elem_width % 8 == 0 && dest_elem_width % 8 == 0);

		auto src_elem_size = src_elem_width / 8;
		auto dest_elem_size = dest_elem_width / 8;
		auto elem_size = std::min(src_elem_size, dest_elem_size);

		auto elem_count = get_num_elements(val.type);
		assert(elem_count = get_num_elements(t));

		// Check if we need to perform sign extensions.
		auto src_int_type = get_integer_type(src_elem_type);
		auto dest_int_type = get_integer_type(dest_elem_type);
		int sign_bit_pos = 0;
		if(src_int_type && dest_int_type)
		{
			if(dest_int_type->width > src_int_type->width && dest_int_type->is_signed && src_int_type->is_signed)
				sign_bit_pos = src_int_type->width;
		}

		TypedValue result{Type{t}};
		result.value.resize(elem_count * dest_elem_size);
		for(int i = 0; i < elem_count; ++i)
		{
			for(int k = 0; k < elem_size; ++k)
				result.value[i * dest_elem_size + k] = val.value[i * src_elem_size + k];

			if(sign_bit_pos)
				sign_extend(&result.value[i * dest_elem_size], dest_elem_size, sign_bit_pos);
		}

		return result;
	}

	throw std::runtime_error{"Can only convert types of the same size or with the same array dimensions"};
}

inline TypedValue make_value(Number value, Type type)
{
	int width = get_bit_width(type);
	assert(width <= 64);

	TypedValue vs{std::move(type)};
	uint8_t const *p = (uint8_t const*)&value.value;
	for(int i = 0; i < width / 8; ++i)
		vs.value[i] = p[i];

	return vs;
}


//------------------------------------------------------------------------------
inline std::ostream& print_dim(std::ostream &os, TypedValue const &ival, Type const &cur_type, int &cur_idx)
{
	if(auto struct_type = get_struct_type(cur_type))
	{
		os << '{';
		for(auto const &m: struct_type->members)
		{
			os << m.first << ": ";
			print_dim(os, ival, *m.second, cur_idx);
			os << "; ";
		}
		os << '}';
	}
	else if(auto arr = get_array_type(cur_type))
	{
		os << '[';
		if(arr->length)
		{
			print_dim(os, ival, *arr->sub, cur_idx);
			for(int i = 1; i < arr->length; ++i)
			{
				os << ", ";
				print_dim(os, ival, *arr->sub, cur_idx);
			}
		}
		os << ']';
	}
	else if(auto it = get_integer_type(cur_type))
		os << get_element(*it, ival.value, cur_idx++);
	else if(auto it = get_bits_type(cur_type))
	{
		assert(cur_idx == 0); // Arrays of bit-types not yet supported
		assert(it->width <= 64);

		uint64_t bits = extract_bits(ival.value, 0, it->width);
		std::stringstream ss; ss << std::bitset<64>(bits);
		auto str = ss.str();
		os << str.substr(str.length() - it->width);
	}

	return os;
}

inline std::ostream& operator << (std::ostream &os, TypedValue const &ival)
{
	if(ival.value.empty())
		os << "<nothing>";
	else
	{
		int cur_idx = 0;
		print_dim(os, ival, ival.type, cur_idx);
	}

	return os;
}

inline std::string to_str(TypedValue const &ival)
{
	std::stringstream ss;
	ss << ival;
	return ss.str();
}

inline std::string bit_string(TypedValue const &val)
{
	std::string bits;
	for_each_bit(val, [&](size_t /*idx*/, bool val)
	{
		bits.push_back(val ? '1' : '0');
	});
		
	std::reverse(bits.begin(), bits.end());
	return bits;
}


//==================================================================================================
// StmtList ::= (Stmt (';' Stmt)* ';'?)?
// Stmt ::= SpecStmt | AssertStmt
// SpecStmt ::= 'spec' ID ':' Type ('=' DomainExpr)?
// AssertStmt ::= 'test' BoolExpr
// AssignStmt ::= VarRefExpr ':' '=' CastExpr
//
// BoolExpr    ::= OrExpr
// OrExpr      ::= AndExpr ('||' AndExpr)*
// AndExpr     ::= CompareExpr ('&&' CompareExpr)*
// CompareExpr ::= CastExpr (('==' | '!=' | '<' | ...) CastExpr)?
//
// CastExpr ::= PrimaryExpr (':' Type)*
// PrimaryExpr ::= VarRefExpr | INT | ARRAY | STRUCT
// VarRefExpr ::= ID
//
// Type ::= 'u'? 'int' ('8' | '16' | '32' | '64') | Type '[' INT ']'

class Context
{
public:
	optional<TypedValue>& get(std::string const &name)
	{
		return m_variables[name];
	}

	optional<TypedValue> const& get(std::string const &name) const
	{
		auto it = m_variables.find(name);
		if(it != m_variables.end())
			return it->second;

		throw std::runtime_error{"variable lookup failed for " + name};
	}

	optional<TypedValue>& add(std::string const &name)
	{
		if(m_variables.find(name) != m_variables.end())
			throw std::runtime_error{"variable " + name + " already defined."};

		return m_variables[name];
	}

	template<typename Func>
	void for_each_variable(Func &&func)
	{
		for(auto const &glob: m_variables)
			func(glob.first, glob.second);
	}

private:
	std::unordered_map<std::string, optional<TypedValue>> m_variables;
};

struct SymbolEntry
{
	enum
	{
		before_readable = 1,
		before_writable = 2,
		after_readable = 4,
		after_writable = 8,

		input = 16 | before_writable | after_readable,
		output = 32 | after_readable,
	};

	Type type;
	int flags;
};

using SymbolTable = std::unordered_map<std::string, SymbolEntry>;


//------------------------------------------------------------------------------
class DomainExpr
{
public:
	virtual ~DomainExpr() = default;

	virtual void print(std::ostream&, bool print_types) const = 0;
	virtual TypedValue evaluate(Context &ctx) const = 0;
	virtual Type const* type() const = 0;
	// Whether the type of the expression was explicitly specified.
	virtual bool has_explicit_type() const = 0;
	virtual bool is_representable_as(Type const &t) const = 0;
	virtual bool is_literal() const = 0;
};

class VarRefExpr : public DomainExpr
{
public:
	VarRefExpr(std::string const &name, Type const &t) :
		m_name{name},
		m_type{t} {}

	virtual Type const* type() const override { return &m_type; }
	virtual bool has_explicit_type() const override { return true; }
	virtual bool is_representable_as(Type const &t) const override
	{
		// m_type is convertible to t if they have a common type.
		return (bool)common_type(m_type, t);
	}

	virtual TypedValue evaluate(Context &ctx) const override
	{
		return ctx.get(m_name).value();
	}

	virtual void print(std::ostream &os, bool print_types) const override
	{
		os << m_name;
		if(print_types)
			os << " : " << m_type;
	}

	virtual bool is_literal() const override { return false; }

	std::string const& name() const { return m_name; }

private:
	std::string m_name;
	Type m_type;
};

class AssignExpr : public DomainExpr
{
public:
	AssignExpr(std::unique_ptr<VarRefExpr> var, std::unique_ptr<DomainExpr> val) :
		m_variable{std::move(var)},
		m_value{std::move(val)} {}

	virtual Type const* type() const override { return m_variable->type(); }
	virtual bool has_explicit_type() const override { return true; }
	virtual bool is_representable_as(Type const &t) const override
	{
		return m_variable->is_representable_as(t);
	}

	virtual TypedValue evaluate(Context &ctx) const override
	{
		auto &val = ctx.get(m_variable->name());
		val  = m_value->evaluate(ctx);
		return *val;
	}

	virtual void print(std::ostream &os, bool print_types) const override
	{
		m_variable->print(os, print_types);
		os << " = ";
		m_value->print(os, print_types);
	}

	virtual bool is_literal() const override { return false; }

private:
	std::unique_ptr<VarRefExpr> m_variable;
	std::unique_ptr<DomainExpr> m_value;
};

class CastExpr : public DomainExpr
{
public:
	CastExpr(Type const &t, std::unique_ptr<DomainExpr> expr) :
		m_expr{std::move(expr)},
		m_type{t} {}

	virtual Type const* type() const override { return &m_type; }
	virtual bool has_explicit_type() const override { return true; }
	virtual bool is_representable_as(Type const &t) const override
	{
		// m_type is convertible to t if they have a common type.
		return (bool)common_type(m_type, t);
	}

	virtual TypedValue evaluate(Context &ctx) const override
	{
		return convert(m_type, m_expr->evaluate(ctx));
	}

	virtual void print(std::ostream &os, bool print_types) const override
	{
		m_expr->print(os, print_types);
		os << " : " << m_type;
	}

	virtual bool is_literal() const override { return m_expr->is_literal(); }

private:
	std::unique_ptr<DomainExpr> m_expr;
	Type m_type;
};

class ValueExpr : public DomainExpr
{
public:
	ValueExpr(TypedValue const &v) :
		m_value{v} {}

	ValueExpr(TypedValue &&v) :
		m_value{std::move(v)} {}

	virtual Type const *type() const override { return &m_value.type; }
	virtual bool has_explicit_type() const override { return false; }

	virtual bool is_representable_as(Type const &t) const override
	{
		return is_representable(t, m_value);
	}

	virtual TypedValue evaluate(Context &ctx) const override
	{
		(void)ctx;
		return m_value;
	}

	virtual void print(std::ostream &os, bool print_types) const override
	{
		os << m_value;
		if(print_types)
			os << " : " << m_value.type;
	}

	virtual bool is_literal() const override { return true; }

private:
	TypedValue m_value;
};


//------------------------------------------------------------------------------
using EvalInfo = std::vector<std::pair<DomainExpr*, TypedValue>>;

class BoolExpr
{
public:
	virtual ~BoolExpr() = default;

	virtual void print(std::ostream &os, bool print_types) const = 0;
	virtual bool evaluate(Context &ctx, EvalInfo &info) const = 0;
};

enum class CmpOp
{
	eq,
	ne,
};

inline char const* to_cstr(CmpOp op)
{
	constexpr char const *conv[] = {"==", "!="};
	return conv[(int)op];
}

class CmpExpr : public BoolExpr
{
public:
	CmpExpr(std::unique_ptr<DomainExpr> l, std::unique_ptr<DomainExpr> r, CmpOp op) :
		m_left{std::move(l)},
		m_right{std::move(r)},
		m_op{op} {}

	virtual bool evaluate(Context &ctx, EvalInfo &info) const override
	{
		auto lv = m_left->evaluate(ctx);
		auto rv = m_right->evaluate(ctx);

		bool result;
		switch(m_op)
		{
			case CmpOp::eq: result = lv == rv; break;
			case CmpOp::ne: result = !(lv == rv); break;
		}

		if(!m_left->is_literal())
			info.push_back({m_left.get(), std::move(lv)});
		if(!m_right->is_literal())
			info.push_back({m_right.get(), std::move(rv)});

		return result;
	}

	virtual void print(std::ostream &os, bool print_types) const override
	{
		os << '(';
		m_left->print(os, print_types);
		os << ' ' << to_cstr(m_op) << ' ';
		m_right->print(os, print_types);
		os << ')';
	}

private:
	std::unique_ptr<DomainExpr> m_left;
	std::unique_ptr<DomainExpr> m_right;
	CmpOp m_op;
};

enum class BinaryBoolOp
{
	l_and,
	l_or,
};

inline char const* to_cstr(BinaryBoolOp op)
{
	constexpr char const *conv[] = {"&&", "||"};
	return conv[(int)op];
}

class BinaryBoolExpr : public BoolExpr
{
public:
	BinaryBoolExpr(std::unique_ptr<BoolExpr> l, std::unique_ptr<BoolExpr> r, BinaryBoolOp op) :
		m_left{std::move(l)},
		m_right{std::move(r)},
		m_op{op} {}


	virtual bool evaluate(Context &ctx, EvalInfo &info) const override
	{
		switch(m_op)
		{
			case BinaryBoolOp::l_and: return m_left->evaluate(ctx, info) && m_right->evaluate(ctx, info);
			case BinaryBoolOp::l_or: return m_left->evaluate(ctx, info) || m_right->evaluate(ctx, info);
		}

		assert(0);
	}

	virtual void print(std::ostream &os, bool print_types) const override
	{
		os << '(';
		m_left->print(os, print_types);
		os << ' ' << to_cstr(m_op) << ' ';
		m_right->print(os, print_types);
		os << ')';
	}

private:
	std::unique_ptr<BoolExpr> m_left;
	std::unique_ptr<BoolExpr> m_right;
	BinaryBoolOp m_op;
};


//------------------------------------------------------------------------------
// Whether a statement should be executed before or after the circuit has been run.
enum class EvalPhase
{
	before,
	after,
};

class Stmt
{
public:
	virtual ~Stmt() {}

	virtual void evaluate(Context &ctx) const = 0;
};

class SpecStmt : public Stmt
{
public:
	SpecStmt(std::string const &var, Type const &t, std::unique_ptr<DomainExpr> val = nullptr) :
		m_var_name{var},
		m_type{t},
		m_value{std::move(val)} {}

	virtual void evaluate(Context &ctx) const override
	{
		if(m_value)
			ctx.get(m_var_name) = m_value->evaluate(ctx);
		else
			ctx.get(m_var_name) = TypedValue{Type{m_type}};
	}
	
private:
	std::string m_var_name;
	Type m_type;
	std::unique_ptr<DomainExpr> m_value;
};

class DomainExprStmt : public Stmt
{
public:
	DomainExprStmt(std::unique_ptr<DomainExpr> expr) :
		m_expr{std::move(expr)} {}

	virtual void evaluate(Context &ctx) const override
	{
		m_expr->evaluate(ctx);
	}
	
private:
	std::unique_ptr<DomainExpr> m_expr;
};

class AssertStmt : public Stmt
{
public:
	AssertStmt(std::unique_ptr<BoolExpr> expr) :
		m_assert{std::move(expr)} {}

	virtual void evaluate(Context &ctx) const override
	{
		EvalInfo info;
		if(m_assert->evaluate(ctx, info))
		{
			std::cout << "[info ] Assertion ";
			m_assert->print(std::cout, false);
			std::cout << " is valid\n";
		}
		else
		{
			std::cout << "[ERROR] Assertion\n\t";
			m_assert->print(std::cout, true);
			std::cout << "\nfailed with values:\n";

			ctx.for_each_variable([](std::string const &name, optional<TypedValue> const &val)
			{
				// TODO Store type (INPUT, OUTPUT) of variables somewhere.
				if(name.compare(0, 6, "INPUT_") == 0 && val)
					std::cout << '\t' << name << " : " << val->type << " = " << *val << '\n';
			});

			for(auto const &val: info)
			{
				std::cout << '\t';
				val.first->print(std::cout, true);
				std::cout << " = " << val.second << std::endl;
			}
		}
	}
	
private:
	std::unique_ptr<BoolExpr> m_assert;
};

class PrintStmt : public Stmt
{
public:
	virtual void evaluate(Context &ctx) const override
	{
		std::vector<std::string> lines;
		ctx.for_each_variable([&](std::string const &name, optional<TypedValue> const &val)
		{
			if(val)
			{
				auto line = name + " : " + to_str(val->type) + " = " + to_str(*val);
				if(val->type.kind() == TypeKind::integer)
					line += " (" + bit_string(*val) + ')';

				lines.push_back(std::move(line));
			}
		});

		std::sort(lines.begin(), lines.end());
		for(auto const &line: lines)
			std::cout << line << '\n';
	}
};

using StmtList = std::vector<std::unique_ptr<Stmt>>;

struct Spec
{
	StmtList before;
	StmtList after;
};


// Parsing
//==================================================================================================
enum class TokenKind
{
	identifier,
	integer_literal,
	brace_left,
	brace_right,
	bracket_left,
	bracket_right,
	colon,
	comma,
	semicolon,
	assign,
	separator,

	eq,
	ne,

	l_and,
	l_or,

	global,
	spec,
	print,

	end,
};

struct SourcePosition
{
	SourcePosition() = default;
	SourcePosition(int l, int c) :
		line{l},
		column{c} {}

	int line, column;
};

struct Token
{
	Token() = default;
	Token(TokenKind k, SourcePosition pos, cstring_ref t = {}) :
		kind{k},
		text{t},
		pos{pos} {}

	TokenKind kind;
	cstring_ref text;
	SourcePosition pos;
};

struct ParseState
{
	explicit ParseState(cstring_ref src, std::string name = "<unnamed_file>") :
		name{name},
		cur{src.b},
		end{src.e},
		source_pos{1, 1}
	{
		next();
	}

	explicit ParseState(char const *str, std::string name = "<unnamed_file>") :
		name{name},
		cur{str},
		end{str + std::strlen(str)},
		source_pos{1, 1}
	{
		next();
	}

	char skip_char()
	{
		if(cur == end)
			return '\0';

		if(*cur == '\n')
		{
			source_pos.line++;
			source_pos.column = 1;
		}
		else
			source_pos.column++;

		return *cur++;
	}

	void skip_char(int n)
	{
		while(n--)
			skip_char();
	}

	bool empty() const { return cur == end; }
	size_t size() const { return end - cur; }

	Token next();

	std::string name;
	char const *cur;
	char const *end;
	Token tok;
	SourcePosition source_pos;
};


// AST nodes for domain expressions
//------------------------------------------------------------------------------
class ExpressionNode
{
public:
	virtual ~ExpressionNode() {}
	virtual std::unique_ptr<DomainExpr> to_domain_expr(SymbolTable const &table, optional<Type> const &type_constraint) = 0;
};


class ValueNode : public ExpressionNode
{
public:
	virtual void to_value(Type const &type, RawValue &value) = 0;
};


class IntegerValueNode : public ValueNode
{
public:
	IntegerValueNode(Number val) :
		m_value{val} {}

	virtual void to_value(Type const &type_constraint, RawValue &value) override
	{
		if(auto int_type = get_integer_type(type_constraint))
		{
			if(is_representable(*int_type, m_value))
			{
				auto p = (uint8_t const*)&m_value.value;
				for(int i = 0; i < int_type->width / 8; ++i)
					value.push_back(p[i]);

				return;
			}
		}

		throw std::runtime_error{"Value " + to_str(m_value) + " not representable by type " + to_str(type_constraint)};
	}

	virtual std::unique_ptr<DomainExpr> to_domain_expr(SymbolTable const &table, optional<Type> const &type_constraint) override
	{
		(void)table;
		if(type_constraint)
		{
			if(auto int_type = get_integer_type(*type_constraint))
			{
				if(is_representable(*int_type, m_value))
					return std::unique_ptr<DomainExpr>{new ValueExpr{make_value(m_value, *type_constraint)}};
			}

			throw std::runtime_error{"Value " + to_str(m_value) + " not representable by type " + to_str(*type_constraint)};
		}

		return std::unique_ptr<DomainExpr>{new ValueExpr{make_value(m_value, find_closest_type(m_value))}};
	}

private:
	Number m_value;
};


class ArrayValueNode : public ValueNode
{
public:
	ArrayValueNode(std::vector<std::unique_ptr<ValueNode>> &&vals) :
		m_values{std::move(vals)} {}

	virtual void to_value(Type const &type_constraint, RawValue &value) override
	{
		if(auto array_type = get_array_type(type_constraint))
		{
			if(array_type->length == (int)m_values.size())
			{
				for(auto &val: m_values)
					val->to_value(*array_type->sub, value);

				return;
			}
		}

		throw std::runtime_error{
			"Cannot convert array of size " + std::to_string(m_values.size()) +
			" to " + to_str(type_constraint)
		};
	}

	virtual std::unique_ptr<DomainExpr> to_domain_expr(SymbolTable const &table, optional<Type> const &type_constraint) override
	{
		(void)table;

		if(!type_constraint)
			throw std::runtime_error{"Arrays require type constraints"};

		RawValue val;
		to_value(*type_constraint, val);
		TypedValue val_spec{Type{*type_constraint}, std::move(val)};

		return std::unique_ptr<DomainExpr>{new ValueExpr{std::move(val_spec)}};
	}

private:
	std::vector<std::unique_ptr<ValueNode>> m_values;
};


using StructValue = std::vector<std::pair<std::string, std::unique_ptr<ValueNode>>>;

class StructValueNode : public ValueNode
{
public:
	StructValueNode(StructValue &&vals) :
		m_value{std::move(vals)} {}

	virtual void to_value(Type const &type_constraint, RawValue &value) override
	{
		if(auto struct_type = get_struct_type(type_constraint))
		{
			if(struct_type->members.size() == m_value.size())
			{
				RawValue new_value;
				for(size_t i = 0; i < struct_type->members.size(); ++i)
				{
					auto const &member_name = struct_type->members[i].first;
					if(member_name != m_value[i].first)
						throw std::runtime_error{"Expected struct member " + member_name + ", got " + m_value[i].first};

					m_value[i].second->to_value(*struct_type->members[i].second, new_value);
				}
				value.insert(value.end(), new_value.begin(), new_value.end());

				return;
			}
		}

		throw std::runtime_error{"Cannot convert struct to " + to_str(type_constraint)};
	}

	virtual std::unique_ptr<DomainExpr> to_domain_expr(SymbolTable const &table, optional<Type> const &type_constraint) override
	{
		(void)table;

		if(!type_constraint)
			throw std::runtime_error{"Structs require type constraints"};

		RawValue val;
		to_value(*type_constraint, val);
		TypedValue val_spec{Type{*type_constraint}, std::move(val)};

		return std::unique_ptr<DomainExpr>{new ValueExpr{std::move(val_spec)}};
	}

private:
	StructValue m_value;
};


class VarRefNode : public ExpressionNode
{
public:
	VarRefNode(std::string const &name) :
		m_name{name} {}

	std::unique_ptr<VarRefExpr> to_var_ref_expr(SymbolTable const &table, optional<Type> const &type_constraint)
	{
		auto it = table.find(m_name);
		if(it == table.end())
			throw std::runtime_error{"Undeclared identifier: " + m_name};

		if(type_constraint && *type_constraint != it->second.type)
		{
			throw std::runtime_error{
				"Invalid type_constraint (" + to_str(*type_constraint) + ") for VarRefNode ("
				+ to_str(it->second.type) + ')'
			};
		}

		return std::unique_ptr<VarRefExpr>{new VarRefExpr{m_name, it->second.type}};
	}

	virtual std::unique_ptr<DomainExpr> to_domain_expr(SymbolTable const &table, optional<Type> const &type_constraint) override
	{
		return to_var_ref_expr(table, type_constraint);
	}

private:
	std::string m_name;
};


class TypeCastNode : public ExpressionNode
{
public:
	TypeCastNode(Type &&t, std::unique_ptr<ExpressionNode> expr) :
		m_target_type{std::move(t)},
		m_expr{std::move(expr)} {}

	virtual std::unique_ptr<DomainExpr> to_domain_expr(SymbolTable const &table, optional<Type> const &type_constraint) override
	{
		(void)table;
		if(type_constraint && *type_constraint != m_target_type)
			throw std::runtime_error{"Invalid type constraint in TypeCastNode"};

		return std::unique_ptr<DomainExpr>{new CastExpr{m_target_type, m_expr->to_domain_expr(table, m_target_type)}};
	}

private:
	Type m_target_type;
	std::unique_ptr<ExpressionNode> m_expr;
};


class AssignmentNode : public ExpressionNode
{
public:
	AssignmentNode(std::unique_ptr<VarRefNode> var, std::unique_ptr<ExpressionNode> value) :
		m_variable{std::move(var)}, 
		m_value{std::move(value)} {}

	virtual std::unique_ptr<DomainExpr> to_domain_expr(SymbolTable const &table, optional<Type> const &type_constraint) override
	{
		auto var_ref = m_variable->to_var_ref_expr(table, type_constraint);
		auto rhs_type = *var_ref->type();

		return std::unique_ptr<DomainExpr>{new AssignExpr{
			std::move(var_ref),
			m_value->to_domain_expr(table, rhs_type)
		}};
	}

private:
	std::unique_ptr<VarRefNode> m_variable;
	std::unique_ptr<ExpressionNode> m_value;
};


//------------------------------------------------------------------------------
Token accept(ParseState &state, TokenKind kind);
Type parse_type(ParseState &state);
std::unique_ptr<ValueNode> parse_value(ParseState &state);
std::unique_ptr<ExpressionNode> parse_cast_expr(ParseState &parser);
std::unique_ptr<ExpressionNode> parse_domain_expr(ParseState &parser);
Spec parse_spec(ParseState &parser, SymbolTable &table);
std::vector<Spec> parse_spec_list(ParseState &parser, SymbolTable &table);

}
