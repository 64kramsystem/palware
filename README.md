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

- `Virus.DOS.LptOff.256` [rca]: disables printing; resides in an unused MS-DOS area (upper IVT table)
- `Virus.DOS.Trivial.Ymir.101` [t]
- `Virus.DOS.SillyOR.81` [t]: testing ground for Ghidra-based analysis
- `Virus.DOS.BadBoy.1000.a` [rc]: splits the virus body in blocks, which are stored (encrypted) in a randomly mixed layout; bypasses Int 13 monitors, if present
- `Virus.DOS.LoveChild.488` [rc]: resides in the upper half of the interrupt table; uses an undocumented DOS 3.30 feature to hijack Int 21
- `Virus.DOS.Tiny.163.a` [rc]: resides in a memory area which is unused after boot
- `Virus.Boot.Stoned.March6.t` [b]: Very famous Stoned variant, known as "Michelangelo"
- `Virus.Boot.Stoned.a` [b]: very famous
- `Virus.DOS.November17.855.a` [rce]: widespread in Italy

Legenda:

- Memory `r`esident
- `b`oot infector
- `c`OM infector
- `e`XE infector
- `t`rojan
- `a`ppending

## Workflow and tools

Previously, the viruses were disassembled via IDA Pro, then the listing exported and manually annotated in a text editor, then tested (for accuracy) with some scripts.

Nowadays, the whole analysis is performed with Ghidra, and the project exported to XML and ASM.

In both cases, the malware is statically analyzed.
