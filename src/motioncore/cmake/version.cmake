# MIT License
#
# Copyright (c) 2020 Lennart Braun
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# Check if we are in a git repository
execute_process(COMMAND "git" "status" RESULTS_VARIABLE GIT_STATUS_RESULT OUTPUT_QUIET ERROR_QUIET)

# Gather information about the current state
if (GIT_STATUS_RESULT EQUAL 0)
  execute_process(COMMAND "git" "describe" "--always" "--dirty" OUTPUT_VARIABLE GIT_VERSION ERROR_QUIET)
  execute_process(COMMAND "git" "rev-parse" "HEAD" OUTPUT_VARIABLE GIT_COMMIT ERROR_QUIET)
  execute_process(COMMAND "git" "rev-parse" "--abbrev-ref" "HEAD" OUTPUT_VARIABLE GIT_BRANCH ERROR_QUIET)
  string(STRIP "${GIT_VERSION}" GIT_VERSION)
  string(STRIP "${GIT_COMMIT}" GIT_COMMIT)
  string(STRIP "${GIT_BRANCH}" GIT_BRANCH)
else ()
  set(GIT_VERSION "N/A")
  set(GIT_COMMIT "N/A")
  set(GIT_BRANCH "N/A")
endif ()

# Write information to version.cpp.new
configure_file("${VERSION_CPP_IN}" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp.new")

# Copy to version.cpp if non-existant or changed
execute_process(COMMAND "${CMAKE_COMMAND}" "-E" "copy_if_different"
                "${CMAKE_CURRENT_BINARY_DIR}/version.cpp.new" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
