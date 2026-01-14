## Introduction

Palware: Paleolitic Malware disassemblies!

This repository contains my disassemblies of DOS viruses.

(For the younger, "DOS" was the dominant consumer operating system of the 80s/early 90s).

## Table of contents

- [Introduction](#introduction)
- [Table of contents](#table-of-contents)
- [Is this (potentially) dangerous?](#is-this-potentially-dangerous)
- [Why reverse engineering \[DOS viruses\]?](#why-reverse-engineering-dos-viruses)
- [Current disassemblies](#current-disassemblies)
- [Workflow and tools](#workflow-and-tools)
- [Candidates for disassembly](#candidates-for-disassembly)

## Is this (potentially) dangerous?

No.

There are several reasons:

1. DOS viruses don't infect modern operating systems; theoretically boot viruses could, but nobody uses floppies anymore;
2. the files are disassemblies, not binaries; ill-intentioned users would need to assemble them first, which is not worth, as other websites already provide live samples (eg. Open Malware);
3. destructive (disk overwriting) code has been removed (even if it wouldn't work on contemporary operating systems anyway);
4. Mikko Hypponen [does it](https://archive.org/details/malwaremuseum), so do I!

## Why reverse engineering [DOS viruses]?

Reverse engineering is a thrilling activity (at least for people interested in low-level programming), as it's an investigative type of work that slowly unfolds.

Malware - at least, the more sophisticated subset of it - is a creative, ingenious, wide-ranging, and sometimes impressive product.

Moreover, reverse engineering is a mentally demanding activity, due to requiring continuous and complete attention; depending on one's interests, this can be simply pleasant, or productive, or both.

## Current disassemblies

In reverse order of completion:

- `Virus.DOS.BadBoy.1000.a`: memory-resident COM-infector
  - highlights:
    - the virus body is split in blocks, which are stored (encrypted) in a randomly mixed layout
    - bypasses Int 13 monitors, if present
- `Virus.DOS.LoveChild.488`: unremarkable memory-resident COM-infector
  - highlights: it resides in the upper half of the interrupt table; it uses an undocumented DOS 3.30 feature to hijack Int 21
- `Virus.DOS.Tiny.163.a`: unremarkable memory-resident COM-infector
  - highlights: it resides in a memory area which is unused after boot
- `Virus.Boot.Stoned.March6.t`: unremarkable variant of Stoned
  - highlights: very famous, under the name "Michelangelo"
- `Virus.Boot.Stoned.a`: unremarkable boot infector
  - highlights: very famous
- `Virus.DOS.November17.855.a`: unremarkable, but competently written, memory-resident, COM/EXE infector
  - highlights: none, but widespread in Italy

## Workflow and tools

The virus sources are mainly the VX Heaven collection and Open Malware.

The binaries are disassembled via IDA Pro, and converted/processed to a NASM-compatible format (via `vx_convert_ida_to_nasm.rb`), which is then statically analyzed.

Before the first research session, the disassembly is compiled back into a "reference" binary, whose purpose is to make sure that no errors are introduced while researching, in particular, in the conversion of numbers to identifiers/operations.

The `vx_compare.sh` script assembles the disassembly, and performs a binary comparison against the reference file,
then visualizes a comparison of the differences, if any is found.

The original file can't be used as reference, because the assembler introduces differences (without functional effects) due to different opcodes which can be used to encode the same instruction, eg:

    (33FF) xor di,di <> (31FF) xor di,di

the reference file has such changes already introduced, so comparing against it will not show them.

## Candidates for disassembly

List of potentially interesting viruses, in order of complexity:

- small (size <= 1k)
  - int13 (512): interesting stealth [VB 199103]
  - 666 (512): interesting cluster infection; sophisticated stealth [VB 199005]
  - dir ii (1024): interesting infection [VB 199111]
- mid  (1K <= size <= 2k)
  - vacsina (earlier yankeedoodle) (1206)
  - 1260 (~1.2k): first poly; anti-debug [VB 199003]
  - cascade (1701): technically advanced
  - caterpillar (~1700): armored
  - jerusalem (~1800): historical
  - mix-1 (1.6k): interesting mem routine; a few payloads [VB 198912]
- mid/large   (2k <= size <= 3k)
  - flip (2153): multipartite; targets av; stealth; armoured; technically advanced [VB 199009]
  - tequila (2400)
  - uruguay v3/5 (2.5k/2.7k)
  - invisible man (2.9k)
  - yankeedoodle (later vacsina) (2.9k+) v33+: self-correcting code; v50+: protected mode
- large (3k+)
  - onehalf (3.5k)
  - commander bomber (4k): inserts in the middle of the host
  - tremor (4k): stealth, etc.
  - frodo/4k: lots of stealth [VB ?]
  - fish #6 (4k, frodo variant): armoured [? VB]
  - uruguay v6 (4.9k+)
  - whale (9k)
  - ssr (18k)
  - ACG (?, C?): metamorphic [VB 199907]
