/*******************************************************************\

Module: Time Stopping

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_UTIL_TIMER_H
#define CPROVER_UTIL_TIMER_H

#include <string>
#include <iosfwd>

#include "time_stopping.h"

class timert
{
private:
  time_periodt _total_time;
  absolute_timet _start_time;
  time_periodt _latest_time;
  long nr_starts;
  bool started;

public:
  timert():
    _total_time(0),
    _start_time(0),
    _latest_time(0),
    nr_starts(0),
    started(false)
  {
  }

  virtual ~timert();

  virtual void start();
  virtual void stop();
  virtual void clear();

  virtual time_periodt total_time() const
  {
    return _total_time;
  }

  virtual fine_timet latest_time() const
  {
    return _latest_time;
  }

  virtual long number_starts() const
  {
    return nr_starts;
  }

  std::string output_total_time() const
  {
    return _total_time.as_string();
  }

  std::string output_latest_time() const
  {
    return _latest_time.as_string();
  }
};

std::ostream &operator<<(std::ostream &out, const timert &timer)
{
  return out << timer.total_time();
}

#endif // CPROVER_UTIL_TIMER_H
