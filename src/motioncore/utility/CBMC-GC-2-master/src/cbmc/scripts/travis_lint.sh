#!/bin/bash

set -e

script_folder=`dirname $0`
pip install --user unidiff

if [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
  $script_folder/run_lint.sh HEAD~1 # Check for errors introduced in last commit
else
  $script_folder/run_lint.sh $TRAVIS_BRANCH # Check for errors compared to merge target
fi

