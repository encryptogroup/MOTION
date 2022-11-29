#include "sat_equivalence_checker.h"

#include <solvers/sat/satcheck.h>


namespace
{

using gates_to_literalt = std::unordered_map<simple_circuitt::gatet const*, literalt>;

literalt convert_gate_to_literal(
	simple_circuitt::gatet const *gate,
	satcheckt &cnf,
	gates_to_literalt &gates_to_literal)
{
	auto it = gates_to_literal.find(gate);
	if(it != gates_to_literal.end())
		return it->second;

	switch(gate->get_operation())
	{
		case simple_circuitt::ONE:
			return gates_to_literal[gate] = const_literal(true);

		case simple_circuitt::INPUT:
			return gates_to_literal[gate] = cnf.new_variable();

		case simple_circuitt::NOT:
		{
			literalt lit = convert_gate_to_literal(gate->get_fanin(0), cnf, gates_to_literal);

			// CAUTION: if you want to use this translation to obtain values by a SAT solver, you have to use lxor instead of lnot!!!
			return gates_to_literal[gate] = neg(lit);

			/*literalt o = cnf.new_variable();
			cnf.lxor(lit, cnf.constant(true), o);
			gate2literal_map[gate] = o;*/
		}

		case simple_circuitt::XOR:
		{
			literalt lit_0 = convert_gate_to_literal(gate->get_fanin(0), cnf, gates_to_literal);
			literalt lit_1 = convert_gate_to_literal(gate->get_fanin(1), cnf, gates_to_literal);
			return gates_to_literal[gate] = cnf.lxor(lit_0, lit_1);
		}

		case simple_circuitt::AND:
		{
			literalt lit_0 = convert_gate_to_literal(gate->get_fanin(0), cnf, gates_to_literal);
			literalt lit_1 = convert_gate_to_literal(gate->get_fanin(1), cnf, gates_to_literal);
			return gates_to_literal[gate] = cnf.land(lit_0, lit_1);
		}

		case simple_circuitt::OR:
		{
			literalt lit_0 = convert_gate_to_literal(gate->get_fanin(0), cnf, gates_to_literal);
			literalt lit_1 = convert_gate_to_literal(gate->get_fanin(1), cnf, gates_to_literal);
			return gates_to_literal[gate] = cnf.lor(lit_0, lit_1);
		}

		default:
			throw std::runtime_error{"Invalid gate operation for SAT sweeping"};
	}
}


tristatet to_tristate(tvt tv)
{
	switch(tv.get_value())
	{
		case tvt::tv_enumt::TV_TRUE: return tri_true;
		case tvt::tv_enumt::TV_FALSE: return tri_false;
		case tvt::tv_enumt::TV_UNKNOWN: return tri_unknown;
	}
}


class sat_resultt : public equivalence_checkert::resultt
{
public:
	virtual bool success() override
	{
		return m_success;
	}

	virtual optional<tristatet> find_value(simple_circuitt::gatet const *gate) override
	{
		auto it = m_gates_to_literal.find(gate);
		if(it == m_gates_to_literal.end())
			return emptyopt;

		return to_tristate(m_cnf.l_get(it->second));
	}

	satcheckt m_cnf;
	gates_to_literalt m_gates_to_literal;
	bool m_success;
};

}


std::unique_ptr<equivalence_checkert::resultt> sat_equivalence_checkert::equals(
	const simple_circuitt::gatet *a,
	const simple_circuitt::gatet *b)
{
	std::unique_ptr<sat_resultt> res{new sat_resultt};

	literalt lit_a = convert_gate_to_literal(a, res->m_cnf, res->m_gates_to_literal);
	literalt lit_b = convert_gate_to_literal(b, res->m_cnf, res->m_gates_to_literal);

	literalt lit_equal = res->m_cnf.lequal(lit_a, lit_b);
	res->m_cnf.l_set_to(lit_equal, false);

	propt::resultt result = res->m_cnf.prop_solve();
	if(result == propt::resultt::P_ERROR)
		throw std::runtime_error{"Error while solving SAT"};

	res->m_success = result == propt::resultt::P_UNSATISFIABLE;

	return std::move(res);
}


std::unique_ptr<equivalence_checkert::resultt> sat_equivalence_checkert::equals(const simple_circuitt::gatet *a, bool value)
{
	std::unique_ptr<sat_resultt> res{new sat_resultt};

	literalt lit_a = convert_gate_to_literal(a, res->m_cnf, res->m_gates_to_literal);
	res->m_cnf.l_set_to(lit_a, value);

	propt::resultt result = res->m_cnf.prop_solve();
	if(result == propt::resultt::P_ERROR)
		throw std::runtime_error{"Error while solving SAT"};

	res->m_success = result == propt::resultt::P_UNSATISFIABLE;

	return std::move(res);
}


std::unique_ptr<equivalence_checkert::resultt> sat_equivalence_checkert::implies(const simple_circuitt::gatet *a, const simple_circuitt::gatet *b)
{
	std::unique_ptr<sat_resultt> res{new sat_resultt};

	literalt lit_a = convert_gate_to_literal(a, res->m_cnf, res->m_gates_to_literal);
	literalt lit_b = convert_gate_to_literal(b, res->m_cnf, res->m_gates_to_literal);

	literalt lit_implies = res->m_cnf.limplies(lit_a, lit_b);
	res->m_cnf.l_set_to(lit_implies, false);

	propt::resultt result = res->m_cnf.prop_solve();
	if(result == propt::resultt::P_ERROR)
		throw std::runtime_error{"Error while solving SAT"};

	res->m_success = result == propt::resultt::P_UNSATISFIABLE;

	return std::move(res);
}
