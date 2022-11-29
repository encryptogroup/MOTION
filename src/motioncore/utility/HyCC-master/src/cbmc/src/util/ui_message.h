/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/


#ifndef CPROVER_UTIL_UI_MESSAGE_H
#define CPROVER_UTIL_UI_MESSAGE_H

#include "message.h"
#include "timestamper.h"

class ui_message_handlert : public message_handlert
{
public:
  enum class uit { PLAIN, XML_UI, JSON_UI };

  ui_message_handlert(
    uit,
    const std::string &program,
    timestampert::clockt clock_type);

  ui_message_handlert(const class cmdlinet &, const std::string &program);

  ui_message_handlert()
    : _ui(uit::PLAIN), time(timestampert::make(timestampert::clockt::NONE))
  {
  }

  virtual ~ui_message_handlert();

  uit get_ui() const
  {
    return _ui;
  }

  void set_ui(uit __ui)
  {
    _ui=__ui;
  }

  virtual void flush(unsigned level) override;

protected:
  uit _ui;
  std::unique_ptr<const timestampert> time;

  virtual void print(
    unsigned level,
    const std::string &message) override;

  virtual void print(
    unsigned level,
    const std::string &message,
    int sequence_number,
    const source_locationt &location) override;

  virtual void print(
    unsigned level,
    const xmlt &data) override;

  virtual void print(
    unsigned level,
    const jsont &data) override;

  virtual void xml_ui_msg(
    const std::string &type,
    const std::string &msg1,
    const std::string &msg2,
    const source_locationt &location);

  virtual void json_ui_msg(
    const std::string &type,
    const std::string &msg1,
    const std::string &msg2,
    const source_locationt &location);

  virtual void ui_msg(
    const std::string &type,
    const std::string &msg1,
    const std::string &msg2,
    const source_locationt &location);

  const char *level_string(unsigned level);
};

#endif // CPROVER_UTIL_UI_MESSAGE_H
