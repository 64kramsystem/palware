# Introduction #

Palware: Paleolitic Malware disassemblies!

This repository contains my disassemblies of DOS viruses.

(For the younger, "DOS" was the dominant consumer operating system of the 80s/early 90s).

# Table of contents #

1. [Is this (potentially) dangerous?](#is-this-potentially-dangerous)
2. [Why reverse engineering [DOS viruses]?](#why-reverse-engineering-dos-viruses)
3. [Current disassemblies](#current-disassemblies)
4. [Workflow and tools](#workflow-and-tools)
5. [Candidates for disassembly](#candidates-for-disassembly)

# Is this (potentially) dangerous? #

No.

There are several reasons:

1. DOS viruses don't infect modern operating systems; theoretically boot viruses could, but nobody uses floppies anymore;
2. the files are disassemblies, not binaries; ill-intentioned users would need to assemble them first, which is not worth, as other websites already provide live samples (eg. Open Malware);
3. destructive (disk overwriting) code has been removed (even if it wouldn't work on contemporary operating systems anyway);
4. Mikko Hypponen [does it](https://archive.org/details/malwaremuseum), so do I!

# Why reverse engineering [DOS viruses]? #

Reverse engineering is a thrilling activity (at least for people interested in low-level programming), as it's an investigative type of work that slowly unfolds.

Malware - at least, the more sophisticated subset of it - is a creative, ingenious, wide-ranging, and sometimes impressive product.

Moreover, reverse engineering is a mentally demanding activity, due to requiring continuous and complete attention; depending on one's interests, this can be simply pleasant, or productive, or both.

# Current disassemblies #

In reverse order of completion:

- `Virus.DOS.BadBoy.1000.a`: interesting memory-resident COM-infector (**WIP**)
- `Virus.DOS.LoveChild.488`: unremarkable memory-resident COM-infector
  - highlights: it resides in the upper half of the interrupt table; it uses an undocumented DOS 3.30 feature to hijack Int 21
- `Virus.DOS.Tiny.163.a`: unremarkable memory-resident COM-infector
  - highlights: it resides in a memory area which is unused after boot
- `Virus.Boot.Stoned.March6.t`: unremarkable, but very famous (under the name "Michelangelo"), variant of Stoned
- `Virus.Boot.Stoned.a`: unremarkable, but very famous, boot infector
- `Virus.DOS.November17.855.a`: unremarkable, but competently written, memory-resident, COM/EXE infector; was widespread in my home country (Italy)

# Workflow and tools #

The virus sources are mainly the VX Heaven collection and Open Malware. The binaries are disassembled via IDA Pro, converted to a NASM-compatible format (via `vx_convert_ida_to_nasm.rb`), and recompiled into a reference binary; finally,  they're statically analyzed.

The reference binary is used for verification during the analysis; the disassembled ASM file is compiled and compared to it via `vx_compare.sh`, to make sure that no errors are introduced, particulary in the conversion of numbers to identifiers (and operations).

By using such "normalized" version, the ASM recompiled binary will match exactly - if it would be instead compared against the original, irrelevant differences would always be found, due to assemblers producing different, although equivalent, opcodes.

# Candidates for disassembly #

List of potentially interesting viruses, in order of complexity:

- small (size <= 1k)
  - int13 (512) [VB 199103]
  - 666 (512): interesting cluster infection; sophisticated stealth [VB 199005]
  - rage (575) [VB 199110]
  - italian (578) [VB 198911]
  - suriv 1.01/402 (~800) [VB 198908]
  - typo (867) [VB 199004]
  - dir ii (1024): interesting infection [VB 199111]
- mid  (1K <= size <= 2k)
  - violator (1055) [VB 199104]
  - datacrime (1168) [VB ?]
  - vacsina (earlier yankeedoodle) (1206)
  - 1260 (~1.2k): first poly; anti-debug [VB 199003]
  - cascade (1701): technically advanced
  - caterpillar (~1700)
  - jerusalem (~1800)
  - mix-1 (1.6k): interesting mem routine; a few payloads [VB 198912]
- mid/large   (2k <= size <= 3k)
  - flip (2153): multipartite; targets av; stealth; armoured; technically advanced
  - tequila (2400)
  - uruguay v3/5 (2.5k/2.7k)
  - invisible man (2.9k)
  - yankeedoodle (later vacsina) (2.9k+) v33+: self-correcting code; v50+: protected mode
  - traceback (3k) [VB ?]
- large (3k+)
  - onehalf (3.5k)
  - commander bomber (4k)
  - tremor [4k]
  - frodo/4k: lots of stealth [VB ?]
  - fish #6 (4k, frodo variant): armoured [? VB]
  - uruguay v6 (4.9k+)
  - whale (9k)
  - ssr (18k)
  - ACG (?, C?): metamorphic
