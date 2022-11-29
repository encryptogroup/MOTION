#pragma once

#include <memory>
#include <vector>
#include <string>
#include <cassert>

// added by Liang Zhao
#include <limits>
#include <stdexcept>
//==================================================================================================
struct BoolType {};

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
	ArrayType(struct Type &&s, int l);

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

	void add_member(std::string const &name, Type &&type);

	std::vector<std::pair<std::string, std::unique_ptr<struct Type>>> members;
};

enum class TypeKind
{
	bits,
	boolean,
	integer,
	array,
	structure,
};

struct Type
{
	Type() :
		Type{BitsType{0}} {}

	Type(BoolType) :
		m_kind{TypeKind::boolean} {}

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
			case TypeKind::boolean: break;
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
			case TypeKind::boolean: break;
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
			case TypeKind::boolean: break;
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
		case TypeKind::boolean:
			return true;
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

inline ArrayType::ArrayType(Type &&s, int l) :
	sub{new Type{std::move(s)}},
	length{l} {}


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

inline void StructType::add_member(std::string const &name, Type &&type)
{
	members.emplace_back(name, std::unique_ptr<Type>{new Type{std::move(type)}});
}


//==================================================================================================
std::ostream& operator << (std::ostream &os, Type const &t);
std::string str(Type const &t);

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

// Returns the number of bits required to represent a value of the given type.
inline size_t get_bit_width(Type const &t)
{
	switch(t.kind())
	{
		case TypeKind::bits: return t.bits().width;
		case TypeKind::boolean: return 1;
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

inline size_t get_num_bytes(Type const &t)
{
	return (get_bit_width(t) + 7) / 8;
}

template<typename Func>
void walk_type_with_path(Type const &type, std::string const &path, Func &&func)
{
	switch(type.kind())
	{
		case TypeKind::bits:
		case TypeKind::boolean:
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
