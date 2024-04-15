#!/bin/bash
###
# SPDX-License-Identifier: MIT
#
#   Copyright (c) 2024, SCANOSS
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#   THE SOFTWARE.
###
#
# Get the defined package version and compare to the latest tag. Echo the new tag if it doesn't already exist.
#
export d=`dirname "$0"`

if [ "$d" = "" ] ; then
  export d=.
fi

version=$(git describe --tags --abbrev=0)
if [[ -z "$version" ]] ; then
  version=$(git describe --tags "$(git rev-list --tags --max-count=1)")
fi
if [[ -z "$version" ]] ; then
  echo "Error: Failed to determine a valid version number" >&2
  exit 1
fi
python_version=$($d/../version.py)
if [ $? -eq 1 ] || [[ "$python_version" = "" ]]; then
  echo "Error: failed to get python app version."
  exit 1
fi
semver_python="v$python_version"

echo "Latest Tag: $version, Python Version: $python_version" >&2

if [[ "$version" == "$semver_python" ]] ; then
  echo "Latest tag and python version are the same: $version" >&2
  exit 1
fi
echo "$semver_python"
exit 0
