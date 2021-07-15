// MIT License
//
// Copyright (c) 2020 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "runtime_info.h"

#include <cassert>
#include <fstream>
#include <iostream>

// So that 'DWORD' in boost/process/detail/windows/handles.hpp is declared
#ifdef __MINGW32__
#include <windows.h>
#include <winbase.h>
#endif

// Because __kernel_entry in boost/process/detail/windows/handle_workaround.hpp isn't defined.
#ifndef __kernel_entry
#define __kernel_entry
#endif

#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <boost/process/pipe.hpp>

namespace encrypto::motion {

std::string GetCmdLine() {
  std::string cmdline;
#if __MINGW32__
  cmdline = GetCommandLine();
#else
  std::ifstream f("/proc/self/cmdline");
  assert(f);
  std::getline(f, cmdline, '\0');
  std::string line;
  while (std::getline(f, line, '\0')) {
    cmdline.append(" ");
    cmdline.append(line);
  }
#endif
  return cmdline;
}

std::size_t GetPid() {
  std::size_t pid;
#if __MINGW32__
  pid = GetCurrentProcessId();
#else
  std::ifstream f("/proc/self/stat");
  assert(f);
  f >> pid;
#endif
  return pid;
}

std::string GetHostname() {
  std::string hostname;
#ifdef __MINGW32__
  LPTSTR name = new TCHAR [MAX_COMPUTERNAME_LENGTH+1];
  LPDWORD size = new DWORD;
  GetComputerName(name, size);
  hostname = std::string(name);
#else
  std::ifstream f("/proc/sys/kernel/hostname");
  assert(f);
  std::getline(f, hostname);
#endif
  return hostname;
}

std::string GetUsername() {
  std::string username;
#ifdef __MINGW32__
  LPTSTR name = new TCHAR [MAX_COMPUTERNAME_LENGTH+1];
  LPDWORD size = new DWORD;
  GetUserName(name, size);
  username = std::string(name);
#else
  namespace bp = boost::process;
  bp::ipstream output;
  bp::child child_process("whoami", bp::std_out > output);
  std::getline(output, username);
#endif
  return username;
}

}  // namespace encrypto::motion
