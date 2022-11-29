#pragma once

#include "circuit.hpp"


namespace circ {

//==================================================================================================
using BitVector = std::vector<ElementID>;

class Builder
{
public:
	explicit Builder(Circuit *circ) :
		m_circuit{circ} {}

	Builder(Builder const&) = delete;


	//--------------------------------------------------------------------------
	BitVector create_inputs(Party party, size_t count)
	{
		BitVector vec;
		vec.reserve(count);
		for(size_t i = 0; i < count; ++i)
			vec.push_back(m_circuit->add_input(party));

		return vec;
	}

	void create_input_variable(std::string const &name, BitVector inputs, Type type)
	{
		std::vector<InputID> is; is.reserve(inputs.size());
		for(size_t i = 0; i < inputs.size(); ++i)
		{
			assert(inputs[i].kind() == ElementID::Kind::input);
			is.push_back(InputID{inputs[i].id()});
		}

		m_circuit->add_input_variable(name, is, type);
	}

	BitVector create_outputs(size_t count)
	{
		BitVector vec;
		vec.reserve(count);
		for(size_t i = 0; i < count; ++i)
			vec.push_back(m_circuit->add_output());

		return vec;
	}

	void create_output_variable(std::string const &name, BitVector inputs, Type type)
	{
		std::vector<OutputID> is; is.reserve(inputs.size());
		for(size_t i = 0; i < inputs.size(); ++i)
		{
			assert(inputs[i].kind() == ElementID::Kind::output);
			is.push_back(OutputID{inputs[i].id()});
		}

		m_circuit->add_output_variable(name, is, type);
	}


	//--------------------------------------------------------------------------
	void connect(BitVector const &from, BitVector const &to)
	{
		assert(from.size() == to.size());

		for(size_t i = 0; i < from.size(); ++i)
			m_circuit->add_wire(from[i], to[i]);
	}

	BitVector zero_vector(size_t width)
	{
		BitVector vec; vec.reserve(width);
		for(size_t i = 0; i < width; ++i)
			vec.push_back(m_circuit->get_or_create_constant_zero());

		return vec;
	}

	void shift_left(BitVector &vec, size_t dist)
	{
		for(size_t i = vec.size() - 1; i >= dist; --i)
			vec[i] = vec[i - dist];

		for(size_t i = 0; i < dist; ++i)
			vec[i] = m_circuit->get_or_create_constant_zero();
	}

	void extend(BitVector &vec, size_t new_width, bool is_signed)
	{
		if(new_width > vec.size())
		{
			auto old_width = vec.size();
			vec.resize(new_width);

			for(size_t i = old_width; i < new_width; ++i)
				vec[i] = is_signed ? vec[old_width-1] : m_circuit->get_or_create_constant_zero();
		}
	}


	//--------------------------------------------------------------------------
	ElementID land(ElementID a, ElementID b)
	{
		auto and_gate = m_circuit->add_gate(GateKind::and_gate);
		m_circuit->add_wire(a, and_gate);
		m_circuit->add_wire(b, and_gate);

		return and_gate;
	}

	void land(BitVector &a, ElementID b)
	{
		for(size_t i = 0; i < a.size(); ++i)
			a[i] = land(a[i], b);
	}

	ElementID lor(ElementID a, ElementID b)
	{
		auto or_gate = m_circuit->add_gate(GateKind::or_gate);
		m_circuit->add_wire(a, or_gate);
		m_circuit->add_wire(b, or_gate);

		return or_gate;
	}

	ElementID lxor(ElementID a, ElementID b)
	{
		auto xor_gate = m_circuit->add_gate(GateKind::xor_gate);
		m_circuit->add_wire(a, xor_gate);
		m_circuit->add_wire(b, xor_gate);

		return xor_gate;
	}

	ElementID lnot(ElementID a)
	{
		auto not_gate = m_circuit->add_gate(GateKind::not_gate);
		m_circuit->add_wire(a, not_gate);

		return not_gate;
	}

	void lnot(BitVector &a)
	{
		for(size_t i = 0; i < a.size(); ++i)
			a[i] = lnot(a[i]);
	}


	// Adder/subtractor
	//--------------------------------------------------------------------------
	std::pair<ElementID, ElementID> full_adder(ElementID a, ElementID b, ElementID carry_in)
	{
		ElementID sum = lxor(a, lxor(b, carry_in));
		ElementID carry_out = lor(land(a, b), land(carry_in, lxor(a, b)));

		return {sum, carry_out};
	}

	ElementID adder(BitVector &a, BitVector const &b, ElementID carry_in)
	{
		assert(a.size() == b.size());

		for(size_t i = 0; i < a.size(); ++i)
			std::tie(a[i], carry_in) = full_adder(a[i], b[i], carry_in);

		return carry_in;
	}

	ElementID adder(BitVector &a, BitVector const &b)
	{
		return adder(a, b, m_circuit->get_or_create_constant_zero());
	}

	ElementID subtractor(BitVector &a, BitVector const &b)
	{
		auto neg_b = b;
		lnot(neg_b);
		return adder(a, neg_b, m_circuit->get_or_create_constant_one());
	}


	// Textbook implementation of a multiplier
	//--------------------------------------------------------------------------
	void multiplier_naive_unsigned(BitVector &a, BitVector const &b)
	{
		assert(a.size() == b.size());

		BitVector prod = zero_vector(a.size());
		BitVector addend = b;
		for(size_t i = 0; i < a.size(); ++i)
		{
			BitVector cond_addend = addend;
			land(cond_addend, a[i]);
			adder(prod, cond_addend);

			shift_left(addend, 1);
		}

		a = prod;
	}

	void multiplier_naive_signed(BitVector &a, BitVector const &b)
	{
		assert(a.size() == b.size());

		assert(!"TODO");
	}

	void multiplier_naive(BitVector &a, BitVector const &b, bool is_signed)
	{
		if(is_signed)
			multiplier_naive_signed(a, b);
		else
			multiplier_naive_unsigned(a, b);
	}


	// Karatsuba multiplication
	// See https://gmplib.org/manual/Karatsuba-Multiplication.html#Karatsuba-Multiplication
	// and https://en.wikipedia.org/wiki/Karatsuba_algorithm
	//--------------------------------------------------------------------------
	void multiplier_karatsuba(BitVector &product, BitVector const &op, bool is_signed)
	{
		assert(product.size() == op.size() * 2 || product.size() == op.size());

		bool overflow = product.size() == op.size() * 2;

		if(op.size() <= 5)
		{
			auto b = op;
			if(overflow)
				extend(b, op.size()*2, is_signed);

			multiplier_naive_unsigned(product, b);

			return;
		}

		int lsb_half = (op.size() + 1) / 2;
		int msb_half = op.size() - lsb_half;
		int full = op.size();

		BitVector x0(product.begin(), product.begin() + lsb_half);
		BitVector x1(product.begin() + lsb_half, product.begin() + full);

		BitVector y0(op.begin(), op.begin() + lsb_half);
		BitVector y1(op.begin() + lsb_half, op.begin() + full);


		BitVector x0_10 = x0; extend(x0_10, lsb_half+2, false); // Least significant part of the number; no sign bit.
		BitVector x1_10 = x1; extend(x1_10, lsb_half+2, is_signed); // Most significant part of the number; may have a sign bit.

		BitVector y0_10 = y0; extend(y0_10, lsb_half+2, false);
		BitVector y1_10 = y1; extend(y1_10, lsb_half+2, is_signed);


		// z1 = x1 * y1
		// Overflow is significant so we need a 16-bit multiplication
		BitVector z1 = x1;
		extend(z1, 2*msb_half, is_signed); // TODO
		multiplier_karatsuba(z1, y1, is_signed);
		extend(z1, full, is_signed);

		// The GNU website says that "(x1-x0)*(y1-y0) is best calculated as an absolute value, and the
		// sign used to choose to add or subtract." What exactly does this mean?

		// z2_a = (x1 - x0)
		// z2_b = (y1 - y0)
		// z2 = z2_a * z2_b
		BitVector z2_a = x1_10;
		subtractor(z2_a, x0_10);
		BitVector z2_b = y1_10;
		subtractor(z2_b, y0_10);

		extend(z2_a, z2_a.size()*2, true); // z2_a and z2_b are the result of a subtraction so always treat them as signed.
		BitVector z2 = z2_a;
		multiplier_karatsuba(z2, z2_b, true);
		extend(z2, full, true);


		// z3 = x0 * y0
		BitVector z3 = x0;
		extend(z3, 2*lsb_half, false);
		multiplier_karatsuba(z3, y0, false);
		extend(z3, full, false);


		//if(overflow)
		{
			extend(z1, 2*full, is_signed);
			extend(z2, 2*full, true);
			extend(z3, 2*full, false);

			BitVector s1 = z1;
			shift_left(s1, lsb_half * 2);

			BitVector s2 = z1;
			shift_left(s2, lsb_half);

			BitVector s3 = z2;
			shift_left(s3, lsb_half);

			BitVector s4 = z3;
			shift_left(s4, lsb_half);

			adder(s1, s2);
			subtractor(s1, s3);
			adder(s1, s4);
			adder(s1, z3);

			product = s1;

			if(!overflow)
				product.resize(full);
		}
	}

private:
	Circuit *m_circuit;
};

}
