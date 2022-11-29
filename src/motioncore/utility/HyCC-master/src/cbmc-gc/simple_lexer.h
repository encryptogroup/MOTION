#pragma once

#include "libcircuit/utils.h"


//==================================================================================================
class lex_statet
{
public:
  lex_statet(cstring_ref source) :
    m_source{source},
    m_cur{m_source.b},
    m_line{1} {}

  lex_statet& next()
  {
    if(m_cur != m_source.e)
    {
      if(*m_cur == '\n')
        m_line++;

      m_cur++;
    }

    return *this;
  }

  bool done() const { return m_cur == m_source.e; }
  char get() const { assert(!done()); return *m_cur; }
  char const* cur() const { return m_cur; }
  int line() const { return m_line; }

  cstring_ref cur_substr(size_t length)
  {
    assert(m_source.e - m_cur >= (ptrdiff_t)length);
    return {m_cur, m_cur + length};
  }

  explicit operator bool () const { return !done(); }

private:
  cstring_ref m_source;
  char const *m_cur;
  int m_line;
};


class parsing_error : public std::runtime_error
{
public:
  parsing_error() = default;
  parsing_error(std::string const &msg) :
    std::runtime_error{msg} {}
};


void skip_whitespaces(lex_statet &lexer);
bool match(lex_statet &lexer, cstring_ref str);
void accept(lex_statet &lexer, cstring_ref str);

cstring_ref read_identifier(lex_statet &lexer);
cstring_ref read_string(lex_statet &lexer);
cstring_ref read_digits(lex_statet &lexer);
cstring_ref read_integer(lex_statet &lexer);
cstring_ref read_decimal(lex_statet &lexer);


inline void accept_skip_ws(lex_statet &lexer, cstring_ref str)
{
	skip_whitespaces(lexer);
	accept(lexer, str);
}

inline bool match_skip_ws(lex_statet &lexer, cstring_ref str)
{
	skip_whitespaces(lexer);
	return match(lexer, str);
}

inline cstring_ref read_identifier_skip_ws(lex_statet &lexer)
{
	skip_whitespaces(lexer);
	return read_identifier(lexer);
}

inline cstring_ref read_string_skip_ws(lex_statet &lexer)
{
	skip_whitespaces(lexer);
	return read_string(lexer);
}

inline bool has_more_skip_sw(lex_statet &lexer)
{
	skip_whitespaces(lexer);
	return !lexer.done();
}
