#include "simple_lexer.h"


void skip_whitespaces(lex_statet &lexer)
{
	while(lexer && std::isspace(lexer.get()))
		lexer.next();
}

void skip_irrelevant(lex_statet &lexer)
{
	while(true)
	{
		skip_whitespaces(lexer);
		if(match(lexer, "//"))
		{
			while(lexer && lexer.get() != '\n')
				lexer.next();

			lexer.next();
		}
		else
			break;
	}
}

bool match(lex_statet &lexer, cstring_ref str)
{
	auto cur_lexer = lexer;
	while(cur_lexer && !str.empty())
	{
		if(cur_lexer.get() != *str.b)
			return false;

		cur_lexer.next();
		++str.b;
	}

	if(!str.empty())
		return false;

	lexer = cur_lexer;
	return true;
}

void accept(lex_statet &lexer, cstring_ref str)
{
	if(!match(lexer, str))
	{
		throw parsing_error{
			std::string{"Expected \""} + str + "\" in line " + std::to_string(lexer.line())
		};
	}
}


cstring_ref read_identifier(lex_statet &lexer)
{
	if(!lexer)
	{
		throw parsing_error{
			"Unexpected end of file, expected identifier in line " + std::to_string(lexer.line())
		};
	}

	if(!std::isalpha(lexer.get()) && lexer.get() != '_')
	{
		throw parsing_error{
			std::string{"Unexpected character '"} + lexer.get() + "', expected letter or '_' in line " +
			std::to_string(lexer.line())
		};
	}

	auto id_begin = lexer.cur();
	while(lexer.next() && (std::isalnum(lexer.get()) || lexer.get() == '_'));

	return {id_begin, lexer.cur()};
}


cstring_ref read_string(lex_statet &lexer)
{
	accept(lexer, "\"");

	auto *str_begin = lexer.cur();
	while(lexer && lexer.get() != '"')
	{
		if(lexer.get() == '\\')
		{
			if(!lexer.next())
			{
				throw parsing_error{
					"Unexpected end of file, expected escape character in line " + std::to_string(lexer.line())
				};
			}
		}

		lexer.next();
	}

	auto *str_end = lexer.cur();
	accept(lexer, "\"");

	return {str_begin, str_end};
}


cstring_ref read_digits(lex_statet &lexer)
{
	cstring_ref digits{lexer.cur(), nullptr};

	while(lexer && std::isdigit(lexer.get()))
		lexer.next();

	digits.e = lexer.cur();
	if(digits.empty())
	{
		throw parsing_error{
			"Expected a digit in line " + std::to_string(lexer.line())
		};
	}

	return digits;
}

cstring_ref read_integer(lex_statet &lexer)
{
	if(!lexer)
	{
		throw parsing_error{
			"Unexpected end of file, expected integer in line " + std::to_string(lexer.line())
		};
	}

	char const *begin = lexer.cur();
	match(lexer, "-");
	return {begin, read_digits(lexer).e};
}

cstring_ref read_decimal(lex_statet &lexer)
{
	if(!lexer)
	{
		throw parsing_error{
			"Unexpected end of file, expected decimal in line " + std::to_string(lexer.line())
		};
	}

	char const *begin = lexer.cur();
	match(lexer, "-");
	if(match(lexer, "."))
		return {begin, read_digits(lexer).e};

	cstring_ref decimal{begin, read_digits(lexer).e};
	if(match(lexer, "."))
	{
		if(lexer && std::isdigit(lexer.get()))
			read_digits(lexer);
	}

	decimal.e = lexer.cur();
	return decimal;
}
