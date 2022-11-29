#pragma once

#include <libcircuit/equivalence_checker.h>

#include <solvers/prop/literal.h>

#include <unordered_map>


class sat_equivalence_checkert : public equivalence_checkert
{
public:
	virtual std::unique_ptr<resultt> equals(simple_circuitt::gatet const *a, simple_circuitt::gatet const *b) override;
	virtual std::unique_ptr<resultt> equals(simple_circuitt::gatet const *a, bool value) override;
	virtual std::unique_ptr<resultt> implies(simple_circuitt::gatet const *a, simple_circuitt::gatet const *b) override;
};
