/*******************************************************************\

Module: A special command line object for Bruce's C Compiler

Author: Michael Tautschnig

\*******************************************************************/

#include <cassert>
#include <iostream>

#include <util/prefix.h>

#include "bcc_cmdline.h"

/*******************************************************************\
 
Function: bcc_cmdlinet::parse
 
  Inputs: argument count, argument strings
 
 Outputs: none
 
 Purpose: parses the commandline options into a cmdlinet

\*******************************************************************/

// non-bcc options
const char *goto_bcc_options_with_argument[]=
{
  "--verbosity",
  "--function",
  "--native-compiler",
  "--native-linker",
  "--print-rejected-preprocessed-source",
  NULL
};

const char *bcc_options_without_argument[]=
{
  "-0",
  "-3",
  "-E",
  "-G",
  "-N",
  "-O",
  "-P",
  "-S",
  "-V",
  "-c",
  "-e",
  "-g",
  "-v",
  "-w",
  "-x",
  "-W",
  "-ansi",
  NULL
};

const char *bcc_options_with_argument[]=
{
  "-A",
  "-B",
  "-D",
  "-U",
  "-M",
  "-o",
  "-C",
  "-P",
  "-I",
  "-L",
  "-T",
  "-Q",
  "-t",
  NULL
};

bool bcc_cmdlinet::parse(int argc, const char **argv)
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
    for(const char **o=goto_bcc_options_with_argument;
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

    // goto-bcc-only command line argument found
    if(found)
      continue;

    // add to new_argv
    add_arg(argv_i);

    // without argument; also store in cmdlinet
    if(in_list(argv_i.c_str(), bcc_options_without_argument))
    {
      set(argv_i);
      continue;
    }

    for(const char **o=bcc_options_with_argument;
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
      std::cerr << "Warning: uninterpreted bcc option '" << argv_i
                << "'" << std::endl;
    }
  }

  return false;
}
