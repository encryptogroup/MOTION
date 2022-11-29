#pragma once

#include <util/type.h>

#include <memory>
#include <ostream>


namespace ir {

class NamedAddrInstr;
class Function;


//==================================================================================================
// ISO C 6.7§5:
//
// "A declaration specifies the interpretation and attributes of a set of identifiers. A definition
// of an identifier is a declaration for that identifier that:
// - for an object, causes storage to be reserved for that object;
// - for a function, includes the function body;
// - for an enumeration constant, is the (only) declaration of the identifier;
// - for a typedef name, is the first (or only) declaration of the identifier."

enum class DeclKind
{
	variable,
	function,
};


class Decl
{
public:
	virtual ~Decl() {}

	DeclKind kind() const { return m_kind; }
	std::string const& name() const { return m_name; }
	typet const& type() const { return m_type; }
	int scope_depth() const { return m_scope_depth; }

protected:
	Decl(DeclKind kind, std::string const &name, typet const &type, int scope_depth) :
		m_kind{kind},
		m_name{name},
		m_type{type},
		m_scope_depth{scope_depth} {}

private:
	DeclKind m_kind;
	std::string m_name;
	typet m_type;
	int m_scope_depth;
};

class VarDecl : public Decl
{
public:
	VarDecl(std::string const &name, typet const &type, int scope_depth,
			bool is_explicit = false) :
		Decl{DeclKind::variable, name, type, scope_depth},
		m_explicit(is_explicit)
	{}

	bool is_explicit() const { return m_explicit; }

private:
	bool m_explicit;
};

class FuncDecl : public Decl
{
public:
	FuncDecl(std::string const &name, typet const &type, int scope_depth) :
		Decl{DeclKind::function, name, type, scope_depth},
		m_function{nullptr}
	{
		assert(type.id() == ID_code);
	}

	bool is_defined() const { return m_function != nullptr; }
	void set_function(std::unique_ptr<Function> &&func);

	Function const* function() const { assert(is_defined()); return m_function.get(); }
	Function* function() { assert(is_defined()); return m_function.get(); }

private:
	std::unique_ptr<Function> m_function;
};


class Scope
{
public:
	explicit Scope(Scope *parent = nullptr) :
		m_parent{parent},
		m_depth{m_parent ? m_parent->depth() + 1 : 0} {}

	Scope(Scope const &rhs) = delete;
	Scope(Scope &&rhs) = delete;

	Scope* create_child()
	{
		m_children.emplace_back(new Scope{this});
		return m_children.back().get();
	}

	Decl* lookup(std::string const &name) const
	{
		if(auto decl = try_lookup(name))
			return decl;

		throw std::runtime_error{"Symbol \"" + name + "\" not found"};
	}

	VarDecl* lookup_var(std::string const &name) const
	{
		Decl *decl = lookup(name);
		if(decl->kind() != DeclKind::variable)
			throw std::runtime_error{"Expected a variable declaration"};

		return static_cast<VarDecl*>(decl);
	}

	FuncDecl* lookup_func(std::string const &name) const
	{
		Decl *decl = lookup(name);
		if(decl->kind() != DeclKind::function)
			throw std::runtime_error{"Expected a function declaration"};

		return static_cast<FuncDecl*>(decl);
	}

	Decl* try_lookup(std::string const &name) const
	{
		auto it = m_symbols.find(name);
		if(it != m_symbols.end())
			return it->second.get();

		if(m_parent)
			return m_parent->try_lookup(name);

		return nullptr;
	}

	VarDecl* declare_var(std::string const &name, typet const &type)
	{
		auto res = m_symbols.insert({name, std::unique_ptr<Decl>{new VarDecl{name, type, m_depth}}});
		if(!res.second)
			throw std::runtime_error{"Symbol \"" + name + "\" already exists"};

		return static_cast<VarDecl*>(res.first->second.get());
	}

	VarDecl* declare_var_explicit(std::string const &name, typet const &type)
	{
		auto res = m_symbols.insert({name, std::unique_ptr<Decl>{new VarDecl{name, type, m_depth, true}}});
		if(!res.second)
			throw std::runtime_error{"Symbol \"" + name + "\" already exists"};

		return static_cast<VarDecl*>(res.first->second.get());
	}

	FuncDecl* declare_func(std::string const &name, typet const &type)
	{
		assert(m_parent == nullptr && "Functions can only be added to the root scope");

		auto res = m_symbols.insert({name, std::unique_ptr<Decl>{new FuncDecl{name, type, m_depth}}});
		if(!res.second)
			throw std::runtime_error{"Symbol \"" + name + "\" already exists"};

		return static_cast<FuncDecl*>(res.first->second.get());
	}

	Decl* declare(std::string const &name, typet const &type)
	{
		if(type.id() == ID_code)
			return declare_func(name, type);

		return declare_var(name, type);
	}

	int depth() const { return m_depth; }
	Scope* parent() const { return m_parent; }

	std::vector<std::unique_ptr<Scope>> const& children() const { return m_children; }
	std::unordered_map<std::string, std::unique_ptr<Decl>> const& symbols() const { return m_symbols; }

	void print(std::ostream &os, int indent = 0) const
	{
		for(auto const &pair: m_symbols)
			os << pair.first << std::endl;

		for(auto const &child: m_children)
			child->print(os, indent + 4);
	}

private:
	// We don't support multiple declarations of the same symbol.
	std::unordered_map<std::string, std::unique_ptr<Decl>> m_symbols;
	Scope *m_parent;
	std::vector<std::unique_ptr<Scope>> m_children;
	int m_depth;
};


class SymbolTable
{
public:
	SymbolTable() = default;
	SymbolTable(SymbolTable const &rhs) = delete;
	SymbolTable(SymbolTable &&rhs) = delete;

	Scope* root_scope() { return &m_root; }
	Scope const* root_scope() const { return &m_root; }

	void print(std::ostream &os) const
	{
		os << ">> Symbol Table <<" << std::endl;
		m_root.print(os);
	}

private:
	Scope m_root;
};

}
