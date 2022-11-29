#include "runner.h"

#include <iostream>


//==================================================================================================
template<typename T>
using limit = std::numeric_limits<T>;

IntegerType find_closest_type(Number n)
{

	if(n.is_neg)
	{
		MaxScalar ival = n.value;
		if(ival >= limit<int8_t>::min())
			return {true, 8};
		else if(ival >= limit<int16_t>::min())
			return {true, 16};
		else if(ival >= limit<int32_t>::min())
			return {true, 32};
		else
			return {true, 64};
	}
	else
	{
		if(n.value <= limit<uint8_t>::max())
			return {n.value <= 127, 8};
		else if(n.value <= limit<uint16_t>::max())
			return {n.value <= 32767, 16};
		else if(n.value <= limit<uint32_t>::max())
			return {n.value <= 2147483647, 32};
		else
			return {n.value <= 9223372036854775807, 64};
	}
}

Number max_value(IntegerType type)
{
	assert(type.width <= 64);

	if(type.is_signed)
		return {false, (1ull << (type.width - 1)) - 1};

	if(type.width == 64)
		return {false, UMaxScalar(-1)};

	return {false, (1ull << type.width) - 1};
}

Number min_value(IntegerType type)
{
	if(type.is_signed)
	{
		auto max_val = max_value(type);
		return {true, ~max_val.value};
	}

	return {false, 0};
}

bool is_representable(IntegerType type, Number n)
{
	return n >= min_value(type) && n <= max_value(type);
}

int next_int_width(int width)
{
	if(width < 8)
		return 8;
	if(width < 16)
		return 16;
	if(width < 32)
		return 32;
	if(width < 64)
		return 64;

	return -1;
}

// Returns the smallest type that can represent both numbers, if there is such a type.
IntegerType common_int_type(Number a, Number b)
{
	if(b < a)
		std::swap(b, a);

	IntegerType type = find_closest_type(b);
	if(is_representable(type, a))
		return type;

	int new_width = next_int_width(type.width);
	if(new_width == -1)
		throw std::runtime_error{"Finding common int type failed"};

	return {true, new_width};
}

// Tries to find an integer type that is a superset of the union of `a` and `b`.
optional<IntegerType> common_int_type(IntegerType a, IntegerType b)
{
	if(b.width < a.width)
		std::swap(a, b);

	bool need_larger_type = 
		(a.width == b.width && a.is_signed != b.is_signed)
		|| (a.width != b.width && a.is_signed && !b.is_signed);

	if(need_larger_type)
	{
		int new_width = next_int_width(b.width);
		if(new_width == -1)
			return emptyopt;

		return IntegerType{true, new_width};
	}
	else
		return b;
}

optional<Type> common_type(Type const &a, Type const &b)
{
	if(a.kind() != b.kind())
		throw std::runtime_error{"No common type"};

	switch(a.kind())
	{
		case TypeKind::bits:
			return Type{BitsType{std::max(a.bits().width, b.bits().width)}};
		case TypeKind::boolean:
			return Type{BoolType{}};
		case TypeKind::integer:
			if(auto ct = common_int_type(a.integer(), b.integer()))
				return Type{*ct};
			else
				return emptyopt;
		case TypeKind::array:
			if(a.array().length != b.array().length)
				return emptyopt;

			if(auto ct = common_type(*a.array().sub, *b.array().sub))
				return make_array_type(std::move(*ct), a.array().length);
			else
				return emptyopt;
		case TypeKind::structure:
			if(a == b)
				return a;
			else
				return emptyopt;
	}

	assert(0);
}

optional<Type> common_type(DomainExpr const *a, DomainExpr const *b)
{
	if(a->has_explicit_type() == b->has_explicit_type())
		return common_type(*a->type(), *b->type());

	if(b->has_explicit_type())
		std::swap(a, b);

	// If the type of `a` is explicitly specified and the type of `b` is not then try to convert `b`
	// to `a`. This may yield a tighter type than using common_type(Type, Type) because
	// is_representable_as() can directly look at the values and not only at the types.
	if(b->is_representable_as(*a->type()))
		return *a->type();

	return common_type(*a->type(), *b->type());
}


//==================================================================================================
char const* to_cstr(TokenKind k)
{
	switch(k)
	{
		case TokenKind::identifier: return "IDENTIFIER";
		case TokenKind::integer_literal: return "INTEGER_LITERAL";
		case TokenKind::brace_left: return "BRACE_LEFT";
		case TokenKind::brace_right: return "BRACE_RIGHT";
		case TokenKind::bracket_left: return "BRACKET_LEFT";
		case TokenKind::bracket_right: return "BRACKET_RIGHT";
		case TokenKind::colon: return "COLON";
		case TokenKind::comma: return "COMMA";
		case TokenKind::semicolon: return "SEMICOLON";
		case TokenKind::assign: return "ASSIGN";
		case TokenKind::separator: return "SEPARATOR";
		case TokenKind::eq: return "EQ";
		case TokenKind::ne: return "NE";
		case TokenKind::l_and: return "L_AND";
		case TokenKind::l_or: return "L_OR";
		case TokenKind::l_true: return "TRUE";
		case TokenKind::l_false: return "FALSE";
		case TokenKind::global: return "GLOBAL";
		case TokenKind::spec: return "SPEC";
		case TokenKind::print: return "PRINT";
		case TokenKind::end: return "END";
	}

	assert(0);
}

void skip_spaces(ParseState &state)
{
	while(state.size() && std::isspace(*state.cur))
		state.skip_char();
}

void skip_line(ParseState &state)
{
	while(state.size() && state.cur[0] != '\n')
		state.skip_char();

	if(state.size() && state.cur[0] == '\n')
		state.skip_char();
}

void skip_multiline_comment(ParseState &parser)
{
	while(parser.size() >= 2)
	{
		if(parser.cur[0] == '*' && parser.cur[1] == '/')
		{
			parser.skip_char(2);
			return;
		}

		parser.skip_char();
	}

	throw std::runtime_error{"Multiline comment not closed"};
}

void skip_comments(ParseState &state)
{
	while(state.size())
	{
		skip_spaces(state);
		if(state.size() >= 2 && state.cur[0] == '/' && state.cur[1] == '/')
			skip_line(state);
		else if(state.size() >= 2 && state.cur[0] == '/' && state.cur[1] == '*')
			skip_multiline_comment(state);
		else
			break;
	}

	skip_spaces(state);
}

[[noreturn]] void throw_parse_error(ParseState const &parser, std::string const &msg, SourcePosition pos)
{
	throw std::runtime_error{
		parser.name + ':' + std::to_string(pos.line) + ':' + std::to_string(pos.column) + ": " + msg
	};
}

[[noreturn]] void throw_parse_error(ParseState const &parser, std::string const &msg)
{
	throw_parse_error(parser, msg, parser.tok.pos);
}

static const std::pair<cstring_ref, TokenKind> g_tokens[] = {
	{"---", TokenKind::separator},
	{"||", TokenKind::l_or},
	{"&&", TokenKind::l_and},
	{"!=", TokenKind::ne},
	{"==", TokenKind::eq},
	{"=", TokenKind::assign},
	{"{", TokenKind::brace_left},
	{"}", TokenKind::brace_right},
	{"[", TokenKind::bracket_left},
	{"]", TokenKind::bracket_right},
	{":", TokenKind::colon},
	{",", TokenKind::comma},
	{";", TokenKind::semicolon},
};

std::pair<cstring_ref, TokenKind> const *find_token(ParseState &parser)
{
	for(auto const &pair: g_tokens)
	{
		if(starts_with(cstring_ref{parser.cur, parser.end}, pair.first))
		{
			parser.skip_char(pair.first.size());
			return &pair;
		}
	}

	return nullptr;
}

Token ParseState::next()
{
	skip_comments(*this);
	auto cur_pos = source_pos;

	if(empty())
		tok = Token{TokenKind::end, cur_pos};
	else if(auto pair = find_token(*this))
		tok = Token{pair->second, cur_pos, pair->first};
	else if(std::isdigit(*cur) || *cur == '-')
	{
		tok = {TokenKind::integer_literal, cur_pos, {cur, cur}};
		if(*cur == '-')
			skip_char();

		while(size() && std::isalnum(*cur))
			skip_char();

		tok.text.e = cur;

		if(*tok.text.b == '-' && tok.text.size() == 1)
			throw_parse_error(*this, "Expected a number after '-'");
	} 
	else if(std::isalpha(*cur))
	{
		tok = {TokenKind::identifier, cur_pos, {cur, cur}};
		skip_char();

		while(size() && (std::isalnum(*cur) || *cur == '_'))
			skip_char();

		tok.text.e = cur;

		if(tok.text == "global")
			tok.kind = TokenKind::global;
		else if(tok.text == "spec")
			tok.kind = TokenKind::spec;
		else if(tok.text == "print")
			tok.kind = TokenKind::print;
		else if(tok.text == "true")
			tok.kind = TokenKind::l_true;
		else if(tok.text == "false")
			tok.kind = TokenKind::l_false;
	}
	else
		throw_parse_error(*this, std::string{"Unexpected character: "} + *cur);

	return tok;
}

Token accept(ParseState &state, TokenKind kind)
{
	if(state.tok.kind == kind)
	{
		auto t = state.tok;
		state.next();
		return t;
	}

	throw_parse_error(state, std::string{"Expected "} + to_cstr(kind) + ", got " + to_cstr(state.tok.kind));
}

bool accept_if(ParseState &state, TokenKind kind)
{
	if(state.tok.kind == kind)
	{
		state.next();
		return true;
	}

	return false;
}

Number parse_int(char const *str, char const *str_end)
{
	errno = 0;
	char *end;
	uint64_t val = strtoull(str, &end, 0);

	if(str == end  || end != str_end)
		throw std::runtime_error{"Unexpected input, expected a number"};

	// TODO For some reason errno is never set. Find out why.
	if(errno == ERANGE)
		throw std::runtime_error{"Integer too big to be parsed"};

	return {*str == '-', val};
}

Number accept_int(ParseState &state)
{
	auto pos = state.tok.pos;
	auto text = accept(state, TokenKind::integer_literal).text;

	try {
		return parse_int(text.b, text.e);
	}
	catch(std::exception const &e) {
		throw_parse_error(state, e.what(), pos);
	}
}


//==================================================================================================
IntegerType lookup_integer_type_name(cstring_ref name)
{
	bool is_signed;
	if(starts_with(name, "int"))
	{
		is_signed = true;
		name.b += 3;
	}
	else if(starts_with(name, "uint"))
	{
		is_signed = false;
		name.b += 4;
	}
	else
		throw std::runtime_error{"Invalid integer type: " + str(name)};

	Number w = parse_int(name.b, name.e);
	if(w.is_neg)
		throw std::runtime_error{"Invalid integer type: " + str(name)};

	return IntegerType{is_signed, (int)w.value};
}

Type parse_array_dimensions(ParseState &state, Type &&sub_type)
{
	if(state.tok.kind == TokenKind::bracket_left)
	{
		state.next();
		int length = accept_int(state).value;
		accept(state, TokenKind::bracket_right);
		return make_array_type(parse_array_dimensions(state, std::move(sub_type)), length);
	}
	else
		return std::move(sub_type);
}

Type parse_scalar_or_struct_type(ParseState &state)
{
	switch(state.tok.kind)
	{
		case TokenKind::brace_left:
		{
			state.next();
			StructType type;
			while(state.tok.kind != TokenKind::brace_right)
			{
				auto id = accept(state, TokenKind::identifier);
				accept(state, TokenKind::colon);
				type.members.emplace_back(str(id.text), std::unique_ptr<Type>{new Type{parse_type(state)}});
				accept(state, TokenKind::semicolon);
			}
			accept(state, TokenKind::brace_right);

			return type;
		} break;

		case TokenKind::identifier:
		{
			auto id = accept(state, TokenKind::identifier);
			if(id.text == "bool")
				return Type{BoolType{}};

			return lookup_integer_type_name(id.text);
		} break;

		default:
			throw_parse_error(state, "Expected type");
	}
}

Type parse_type(ParseState &state)
{
	return parse_array_dimensions(state, parse_scalar_or_struct_type(state));
}


//------------------------------------------------------------------------------
std::unique_ptr<ValueNode> parse_value(ParseState &state)
{
	// Parse array
	if(accept_if(state, TokenKind::bracket_left))
	{
		std::vector<std::unique_ptr<ValueNode>> values;
		if(state.tok.kind != TokenKind::bracket_right)
		{
			values.push_back(parse_value(state));
			while(state.tok.kind != TokenKind::bracket_right)
			{
				accept(state, TokenKind::comma);
				values.push_back(parse_value(state));
			}
			accept(state, TokenKind::bracket_right);
		}

		return std::unique_ptr<ValueNode>{new ArrayValueNode{std::move(values)}};
	}
	// Parse struct
	else if(accept_if(state, TokenKind::brace_left))
	{
		StructValue value;
		while(state.tok.kind != TokenKind::brace_right)
		{
			auto id = accept(state, TokenKind::identifier);
			accept(state, TokenKind::colon);
			value.emplace_back(str(id.text), parse_value(state));
			accept(state, TokenKind::semicolon);
		}
		accept(state, TokenKind::brace_right);

		return std::unique_ptr<ValueNode>{new StructValueNode{std::move(value)}};
	}
	// Parse integer
	else if(state.tok.kind == TokenKind::integer_literal)
		return std::unique_ptr<ValueNode>{new IntegerValueNode{accept_int(state)}};
	// Parse boolean
	else if(accept_if(state, TokenKind::l_true))
		return std::unique_ptr<ValueNode>{new BooleanValueNode{true}};
	else if(accept_if(state, TokenKind::l_false))
		return std::unique_ptr<ValueNode>{new BooleanValueNode{false}};

	throw_parse_error(state, std::string{"Expected value, got "} + to_cstr(state.tok.kind));
}


// Parsing DomainExpr
//------------------------------------------------------------------------------
std::unique_ptr<VarRefNode> parse_var_ref_expr(ParseState &parser)
{
	auto name = str(accept(parser, TokenKind::identifier).text);
	return std::unique_ptr<VarRefNode>{new VarRefNode{name}};
}

std::unique_ptr<ExpressionNode> parse_primary_expr(ParseState &parser)
{
	switch(parser.tok.kind)
	{
		case TokenKind::integer_literal:
		case TokenKind::bracket_left:
		case TokenKind::brace_left:
			return parse_value(parser);
		case TokenKind::identifier:
			return parse_var_ref_expr(parser);
		default:
			throw_parse_error(parser, "Expected value or identifier");
	}
}

std::unique_ptr<ExpressionNode> parse_cast_expr(ParseState &parser)
{
	auto expr = parse_primary_expr(parser);
	while(parser.tok.kind == TokenKind::colon)
	{
		parser.next();
		auto type = parse_type(parser);
		expr = std::unique_ptr<ExpressionNode>(new TypeCastNode{std::move(type), std::move(expr)});
	}

	return expr;
}

std::unique_ptr<ExpressionNode> parse_assign_expr(ParseState &parser)
{
	auto var_expr = parse_var_ref_expr(parser);

	accept(parser, TokenKind::colon);
	accept(parser, TokenKind::assign);

	auto value = parse_cast_expr(parser);
	return std::unique_ptr<ExpressionNode>{new AssignmentNode{std::move(var_expr), std::move(value)}};
}

std::unique_ptr<ExpressionNode> parse_domain_expr(ParseState &parser)
{
	return parse_assign_expr(parser);
}


// Parsing BoolExpr
//------------------------------------------------------------------------------
CmpOp accept_cmp_op(ParseState &parser)
{
	switch(parser.tok.kind)
	{
		case TokenKind::eq: parser.next(); return CmpOp::eq;
		case TokenKind::ne: parser.next(); return CmpOp::ne;
		default: throw_parse_error(parser, std::string{"Expected `==` or '!=', got "} + to_cstr(parser.tok.kind));
	}
}

std::unique_ptr<BoolExpr> parse_compare_expr(ParseState &parser, SymbolTable const &table)
{
	auto left = parse_cast_expr(parser)->to_domain_expr(table, emptyopt);
	auto op = accept_cmp_op(parser);
	auto right = parse_cast_expr(parser)->to_domain_expr(table, *left->type());

	assert(*right->type() == *left->type());

	return std::unique_ptr<BoolExpr>{new CmpExpr{std::move(left), std::move(right), op}};
}

std::unique_ptr<BoolExpr> parse_and_expr(ParseState &parser, SymbolTable const &table)
{
	auto expr = parse_compare_expr(parser, table);
	while(parser.tok.kind == TokenKind::l_and)
	{
		parser.next();
		expr = std::unique_ptr<BoolExpr>{new BinaryBoolExpr{
			std::move(expr), parse_compare_expr(parser, table), BinaryBoolOp::l_and}
		};
	}

	return expr;
}

std::unique_ptr<BoolExpr> parse_or_expr(ParseState &parser, SymbolTable const &table)
{
	auto expr = parse_compare_expr(parser, table);
	while(parser.tok.kind == TokenKind::l_or)
	{
		parser.next();
		expr = std::unique_ptr<BoolExpr>{new BinaryBoolExpr{
			std::move(expr), parse_compare_expr(parser, table), BinaryBoolOp::l_or}
		};
	}

	return expr;
}

std::unique_ptr<BoolExpr> parse_bool_expr(ParseState &parser, SymbolTable const &table)
{
	return parse_or_expr(parser, table);
}


//------------------------------------------------------------------------------
std::pair<EvalPhase, std::unique_ptr<Stmt>> parse_spec_stmt(ParseState &parser, SymbolTable &table)
{
	accept(parser, TokenKind::spec);
	auto name = str(accept(parser, TokenKind::identifier).text);
	accept(parser, TokenKind::colon);
	auto type = parse_type(parser);

	std::unique_ptr<DomainExpr> val;
	if(accept_if(parser, TokenKind::assign))
		val = parse_value(parser)->to_domain_expr(table, type);

	auto entry_it = table.find(name);
	if(entry_it == table.end())
		throw_parse_error(parser, "spec-statement: unknown variable " + name);

	SymbolEntry &entry = entry_it->second;
	EvalPhase phase = EvalPhase::before;
	if(entry.flags == SymbolEntry::input || entry.flags == SymbolEntry::output)
	{
		if(entry.flags == SymbolEntry::output && val)
			throw_parse_error(parser, "spec-statement: assignment to output varianle " + name + " not allowed");
	}
	else
		throw_parse_error(parser, "spec-statement: variable " + name + " is neither input nor output");

	entry.type = type;

	return {phase, std::unique_ptr<Stmt>{new SpecStmt{name, type, std::move(val)}}};
}

static bool is_assign_expr(ParseState parser /*by value*/)
{
	return
		accept_if(parser, TokenKind::identifier) &&
		accept_if(parser, TokenKind::colon) &&
		accept_if(parser, TokenKind::assign);
}

std::pair<EvalPhase, std::unique_ptr<Stmt>> parse_stmt(ParseState &parser, SymbolTable &table)
{
	switch(parser.tok.kind)
	{
		case TokenKind::spec:
			return parse_spec_stmt(parser, table);
		case TokenKind::print:
			parser.next();
			return {EvalPhase::after, std::unique_ptr<Stmt>{new PrintStmt{}}};
		default:
			if(is_assign_expr(parser))
			{
				auto expr = parse_domain_expr(parser)->to_domain_expr(table, emptyopt);
				return {EvalPhase::before, std::unique_ptr<Stmt>{new DomainExprStmt{std::move(expr)}}};
			}
			else
			{
				// TODO For now, simple execute assertions after the circuit has been run. For the future,
				//      make it possible for assertions to be executed before.
				return {EvalPhase::after, std::unique_ptr<Stmt>{new AssertStmt{parse_bool_expr(parser, table)}}};
			}
	}
}

Spec parse_spec(ParseState &parser, SymbolTable &table)
{
	Spec spec;
	while(parser.tok.kind != TokenKind::end && parser.tok.kind != TokenKind::separator)
	{
		auto stmt = parse_stmt(parser, table);
		if(stmt.first == EvalPhase::before)
			spec.before.push_back(std::move(stmt.second));
		else
			spec.after.push_back(std::move(stmt.second));

		accept(parser, TokenKind::semicolon);
	}

	if(spec.before.empty() && spec.after.empty())
		throw_parse_error(parser, "Expected statements");

	return spec;
}

std::vector<Spec> parse_spec_list(ParseState &parser, SymbolTable &table)
{
	std::vector<Spec> specs;
	while(parser.tok.kind != TokenKind::end)
	{
		specs.push_back(parse_spec(parser, table));
		if(parser.tok.kind == TokenKind::separator)
			parser.next();
	}

	return specs;
}
