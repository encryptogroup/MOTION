/*******************************************************************\

Module: A special command line object for as86 (of Bruce's C Compiler)

Author: Michael Tautschnig

\*******************************************************************/

#include <cassert>
#include <iostream>

#include <util/prefix.h>

#include "as86_cmdline.h"

/*******************************************************************\
 
Function: as86_cmdlinet::parse
 
  Inputs: argument count, argument strings
 
 Outputs: none
 
 Purpose: parses the commandline options into a cmdlinet

\*******************************************************************/

// non-as86 options
const char *goto_as86_options_with_argument[]=
{
  "--verbosity",
  "--function",
  "--native-assembler",
  "--print-rejected-preprocessed-source",
  NULL
};

const char *as86_options_without_argument[]=
{
  "-0",
  "-1",
  "-2",
  "-3",
  "-a",
  "-g",
  "-j",
  "-O",
  "-u",
  "-u-", // both -u and -u- seem to be accepted
  "-v",
  "-w-",
  NULL
};

const char *as86_options_with_argument[]=
{
  "-lm",
  "-l",
  "-n",
  "-o",
  "-b",
  "-s",
  "-t",
  NULL
};

bool as86_cmdlinet::parse(int argc, const char **argv)
{
  assert(argc>0);
  add_arg(argv[0]);

  for(int i=1; i<argc; i++)
  {
    std::string argv_i=argv[i];

    // file?
    if(argv_i=="-" || !has_prefix(argv_i, "-"))
    {
      add_infile_arg(argv_i);
      continue;
    }

    bool found=false;

    // separated only, and also allow concatenation with "="
    for(const char **o=goto_as86_options_with_argument;
        *o!=NULL && !found;
        ++o)
    {
      std::string os(*o);

      if(argv_i==os) // separated
      {
        found=true;
        if(i!=argc-1)
        {
          set(argv_i, argv[i+1]);
          ++i;
        }
        else
          set(argv_i, "");
      }
      else if(has_prefix(argv_i, os+"=")) // concatenated with "="
      {
        found=true;
        set(os, argv_i.substr(os.size()+1));
      }
    }

    // goto-as86-only command line argument found
    if(found)
      continue;

    // add to new_argv
    add_arg(argv_i);

     // without argument; also store in cmdlinet
    if(in_list(argv_i.c_str(), as86_options_without_argument))
    {
      set(argv_i);
      continue;
    }

    for(const char **o=as86_options_with_argument;
        *o!=NULL && !found;
        ++o)
    {
      std::string os(*o);

      if(argv_i==os) // separated
      {
        found=true;
        if(i!=argc-1)
        {
          set(argv_i, argv[i+1]);
          add_arg(argv[i+1]);
          ++i;
        }
        else
          set(argv_i, "");
      }
      else if(has_prefix(argv_i, os))
      {
        found=true;
        set(os, argv[i]+os.size());
      }
    }

    if(!found)
    {
      // unrecognized option
      std::cerr << "Warning: uninterpreted as86 option '" << argv_i
                << "'" << std::endl;
    }
  }

  return false;
}
