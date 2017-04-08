#!/bin/bash

set -o errexit

sync_points_file=sync_points

default_reference_bin=reference.com

research_asm=research.asm
temp_research_bin=/tmp/research.com
temp_research_disasm=/tmp/research.dis.asm

if [[ $# > 1 ]] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "Compares the disassembly of the reference with the assembly+disassembly of \`$research_asm\`."
  echo "This script is used to double check that modifications to \`$research_asm\` results in the same binary as the reference."
  echo
  echo "Optionally, <reference> can be specified. This is used on the first time, to make sure that the reference disassembly doesn't diverge significantly from the original binary."
  echo
  echo "Usage: vx_compare.sh [reference]"
else
  if [ "$1" != "" ]; then
    reference_bin=$1
  else
    reference_bin=$default_reference_bin
  fi

  if [ -e $sync_points_file ]; then
    sync_points_param="-s $(<$sync_points_file)"
  fi

  temp_reference_disasm="/tmp/${reference_bin%.*}.dis.asm"

  nasm $research_asm -o $temp_research_bin

  if [[ $(md5sum $reference_bin | awk '{print $1}') = $(md5sum $temp_research_bin | awk '{print $1}') ]]; then
    echo "Compiled binary matches the reference!"
  else
    ndisasm -o100h $sync_points_param $reference_bin > $temp_reference_disasm
    ndisasm -o100h $sync_points_param $temp_research_bin > $temp_research_disasm

    meld $temp_reference_disasm $temp_research_disasm
  fi
fi
