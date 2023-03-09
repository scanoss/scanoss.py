#!/bin/bash
###
# SPDX-License-Identifier: MIT
#
#   Copyright (c) 2022, SCANOSS
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
# Attempt to download an SSL certificate from the specified host and convert to a PEM file
#

script_name=$(basename $0)

help()
{
  echo "Usage: $script_name -n <hostname> [-p <port>] [-o pem-file] [-f] [-h]
           -n  -- Hostname to download certificate from
           -p  -- Port number to use (default 443)
           -o  -- Output filename (default <hostname>.pem)
           -f  -- Force the overwrite of existing pem file"
  exit 2
}

SHORT=n:,p:o:,h,f
OPTS=$(getopt $SHORT "$@")
if [[ $? -ne 0 ]]; then
  help
fi
VALID_ARGUMENTS=$#
if [ "$VALID_ARGUMENTS" -eq 0 ]; then  # No arguments supplied, print help
  help
fi
set -- $OPTS

force=0
while :; do
#  echo "1: $1 - 2: $2"
  case "$1" in
    -n )
      host="$2"
      shift 2
      ;;
    -p )
      port="$2"
      shift 2
      ;;
    -o )
      pemfile="$2"
      shift 2
      ;;
    -f )
      force=1
      shift
      ;;
    -h )
      help
      ;;
    --)
      shift;
      break
      ;;
    *)
      echo "Unexpected option: $1"
      help
      ;;
  esac
done

if [ -z "$host" ] ; then
  echo "Error: Please provide a hostname -h <host>"
  exit 1
fi
if [ -z "$port" ] ; then
  port="443"
fi
if [ -z "$pemfile" ] ; then
  pemfile="${host}.pem"
fi

if [ $force -eq 0 ] && [ -f "$pemfile" ] ; then
  echo "Error: Output PEM file already exists: $pemfile"
  exit 1
fi
echo "Attempting to get PEM certificate from $host:$port and saving to $pemfile ..."

openssl s_client -showcerts -verify 5 -connect "$host:$port" -servername "$host" < /dev/null 2> /dev/null | awk '/BEGIN/,/END/{ if(/BEGIN/){a++}; print}' > "$pemfile"
