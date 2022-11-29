#pragma once

#include <string>
#include <memory>
#include <vector>
#include <sstream>
#include <iostream>


enum class log_levelt
{
	none,
	error,
	warning,
	info,
	statistics,
	debug,
};

inline bool operator < (log_levelt a, log_levelt b) { return (int)a < (int)b; }
inline bool operator <= (log_levelt a, log_levelt b) { return (int)a <= (int)b; }
inline bool operator > (log_levelt a, log_levelt b) { return (int)a > (int)b; }
inline bool operator >= (log_levelt a, log_levelt b) { return (int)a >= (int)b; }


class log_targett
{
public:
	virtual void write(log_levelt cur_level, log_levelt msg_level, std::string const &msg) = 0;
};


class default_log_targett : public log_targett
{
public:
	virtual void write(log_levelt cur_level, log_levelt msg_level, std::string const &msg) override
	{
		if(msg_level <= cur_level)
			std::cout << msg;
	}
};


// End-of-message tag
struct eomt {};
constexpr eomt eom;

class log_messaget
{
public:
	log_messaget(class loggert *logger, log_levelt level) :
		m_logger{logger},
		m_level{level} {}

	template<typename T>
	log_messaget& operator << (T const &v)
	{
		m_buffer << v;
		return *this;
	}

	inline log_messaget& operator << (eomt);

private:
	class loggert *m_logger;
	std::ostringstream m_buffer;
	log_levelt m_level;
};

class loggert
{
public:
	loggert() :
		m_level{log_levelt::statistics} {}

	template<typename T, typename ...Args>
	T* add_target(Args &&...args)
	{
		m_targets.push_back(std::unique_ptr<T>{new T(std::forward<Args>(args)...)});
		return static_cast<T*>(m_targets.back().get());
	}

	log_messaget error() { return log_messaget{this, log_levelt::error}; }
	log_messaget warning() { return log_messaget{this, log_levelt::warning}; }
	log_messaget info() { return log_messaget{this, log_levelt::info}; }
	log_messaget statistics() { return log_messaget{this, log_levelt::statistics}; }
	log_messaget debug() { return log_messaget{this, log_levelt::debug}; }

	log_levelt level() const { return m_level; }
	void level(log_levelt level) { m_level = level; }

	void write(log_levelt level, std::string const &msg)
	{
		for(auto &target: m_targets)
			target->write(m_level, level, msg);
	}

private:
	std::vector<std::unique_ptr<log_targett>> m_targets;
	log_levelt m_level;
};


log_messaget& log_messaget::operator << (eomt)
{
	m_buffer << '\n';
	m_logger->write(m_level, m_buffer.str());
	m_buffer.str("");
	return *this;
}


loggert& default_logger();

