#pragma once

#include "simple_circuit.h"


enum tristatet : uint8_t
{
	tri_true,
	tri_false,
	tri_unknown,
};

inline bool to_bool(tristatet tri)
{
	if(tri == tri_unknown)
		throw std::runtime_error{"tristate is unknown"};

	return tri == tri_true;
}


class equivalence_checkert
{
public:
	class resultt
	{
	public:
		virtual bool success() = 0;
		virtual optional<tristatet> find_value(simple_circuitt::gatet const *gate) = 0;
	};

	virtual std::unique_ptr<resultt> equals(simple_circuitt::gatet const *a, simple_circuitt::gatet const *b) = 0;
	virtual std::unique_ptr<resultt> equals(simple_circuitt::gatet const *a, bool value) = 0;
	virtual std::unique_ptr<resultt> implies(simple_circuitt::gatet const *a, simple_circuitt::gatet const *b) = 0;

};

