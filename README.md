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
- [Interesting specimens](#interesting-specimens)

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

## Interesting specimens

| Name             | Size  | Notes                                                                                                                                                                                     |
| ---------------- | :---: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Synergy          |  288  | Hides resident body in monochrome video adapter memory (B000) — invisible to conventional RAM scanners                                                                                    |
| Twin-351         |  351  | Companion: creates shadow .COM per each .EXE, leaves original untouched — invisible to size-based detection                                                                               |
| Azusa            |  368  | (VB 199104)                                                                                                                                                                               |
| Cinderella       |  390  | Hooks INT 2Eh (DOS internal command dispatcher) instead of INT 21h — bypasses TSR-based AV monitors                                                                                       |
| Olya             |  398  | EXE-only stealth: both CHKDSK memory and IVT appear clean — dual stealth in an EXE infector under 400 bytes                                                                               |
| DoDo             |  408  | Hides in CGA/EGA adapter buffer memory, same trick as Synergy                                                                                                                             |
| Suriv            | 415+  | Ancestor of Jerusalem                                                                                                                                                                     |
| ZeroHunt         |  416  | Overwriting stealth: hooks interrupts to make destroyed files appear intact to directory listings and reads                                                                               |
| Turbo            |  448  | Installs resident inside COMMAND.COM's own memory block — consumes zero MCB-tracked allocations                                                                                           |
| Bit Addict       |  477  | Splits itself across conventional memory and video adapter memory to frustrate removal                                                                                                    |
| LoveChild        |  488  | (VB 199102)                                                                                                                                                                               |
| LockUp           |  496  | Companion/spawning for .EXE with stealth to hide the created .COM companion files                                                                                                         |
| 500              |  500  | Intentionally does not reserve its own resident memory — makes forensic memory analysis inconsistent                                                                                      |
| Boys             |  500  | Resident with no CHKDSK memory change and no visible hooks, without using the standard TSR mechanism                                                                                      |
| MG               |  500  | Installs resident body inside unused IVT slots — lives literally inside the interrupt vector table                                                                                        |
| Genc             |  502  | Infects .COM and .SYS device driver files — persists through driver loads, not just program execution                                                                                     |
| Hobbit           |  505  | Resident EXE stealth that hooks no IVT entries — invisible to scanners checking the interrupt table                                                                                       |
| A&A              |  506  | Interrupt tunneling: traces INT 21h chain past installed TSRs to reach original DOS handler directly                                                                                      |
| 666              |  512  | (VB 199005) Interesting cluster infection; sophisticated stealth                                                                                                                          |
| Aircop           |  512  | (VB 199102)                                                                                                                                                                               |
| Beijing          |  512  | (VB 199102)                                                                                                                                                                               |
| Costeau          |  512  | Hides resident body in the DOS Data Area — invisible to MCB chain walkers                                                                                                                 |
| Disk killer      |  512  | (VB 199001)                                                                                                                                                                               |
| Evil Empire      |  512  | (VB 199105)                                                                                                                                                                               |
| Form             |  512  | (VB 199111)                                                                                                                                                                               |
| Int13            |  512  | (VB 199103) Interesting stealth                                                                                                                                                           |
| Fission          |  517  | Infects .BAT files in addition to .COM and .EXE — unusual target for this size                                                                                                            |
| Quake            |  518  | Hides inside DOS buffers — total and free memory figures show no change to diagnostic tools                                                                                               |
| Rage             |  575  | (VB 199110)                                                                                                                                                                               |
| Vienna           |  623  | (VB 199007)                                                                                                                                                                               |
| Sinep            |  644  | Goes resident hooking only INT 22 (program terminate address), not INT 21                                                                                                                 |
| ETC              |  700  | Hooks INT 00 (divide-by-zero exception) instead of INT 21 for persistence — CHKDSK totals unaltered                                                                                       |
| 708              |  708  | Installs via INT 08 (hardware timer) instead of INT 21, immediately infects COMMAND.COM on first load                                                                                     |
| WMA              |  709  | Stealth .EXE infector that actively hides the file length increase when resident, in under 710 bytes                                                                                      |
| Doomsday         |  733  | After infecting, directly accesses the hard disk at hardware level to produce an audible scraping sound                                                                                   |
| 10 Past 3        |  748  | Hooks INT 6Bh (undocumented BIOS/AT interrupt) in addition to INT 21h to complicate tracing                                                                                               |
| PMT              |  867  | Encrypted companion: creates .COM companions for .EXE files — combines encryption and companion technique                                                                                 |
| Typo             |  867  | (VB 199004)                                                                                                                                                                               |
| Hell             |  936  | Non-resident infector that also drops a fragment hooked to INT 1C (system clock) — split resident/non-resident design                                                                     |
| Freak            |  942  | Alternates on each execution: either infects a new file or removes itself from a previously infected one                                                                                  |
| Forger           | 1000  | Hooks INT CCh (software breakpoint trap) alongside INT 21h — specifically to interfere with debugger analysis                                                                             |
| Tester           | 1000  | Presents an interactive menu asking the user whether to infect files or just run the program                                                                                              |
| Dir II           | 1024  | (VB 199111) Interesting infection                                                                                                                                                         |
| Italian (Pong)   | 1024  | (VB copyrighted)                                                                                                                                                                          |
| Nomenklatura     | 1024  | (VB 199012)                                                                                                                                                                               |
| Junkie           | 1030  | True multipartite: infects boot sectors, MBR, and .COM files simultaneously; confirmed in the wild across five countries                                                                  |
| Pisello          | 1030  | Hooks INT F8 (unused/reserved vector) with additional hooks that don't appear in memory maps — double-layer evasion                                                                       |
| Violator         | 1055  | (VB 199104)                                                                                                                                                                               |
| Soupy            | 1072  | On the 11th infection generation displays countdown taunts every 3 minutes ending with '...I think I'll halt now...' then freezes                                                         |
| KeyKap           | 1074  | Companion/spawning via hidden .COM files for .EXE targets; hooks INT 09 (keyboard) and INT 13 (disk) in addition to INT 21                                                                |
| Armagedon        | 1079  | Between 5–7 AM uses the modem to dial the Local Time Information service in Crete and leaves the line open; also sends a string to COM1–4 at timed intervals                              |
| Datacrime        | 1168  | Triggered low-level hard disk format on Oct 12–Dec 31; caused widespread 1989 media panic ('Columbus Day virus')                                                                          |
| Faust            | 1181  | (VB 199102)                                                                                                                                                                               |
| Dark End         | 1188  | TSR that impersonates COMMAND.COM in memory maps, disguising itself inside the interpreter's MCB entry                                                                                    |
| Vacsina          | 1206  | (TPnn, increasing complexity) Infects .COM, .EXE, .SYS, and .BIN (four types); evolved into Yankee Doodle across 48+ documented variants                                                  |
| Pathhunt         | 1231  | When it runs out of executables, corrupts .DBF files; renames each target to 'PATHHUNT' during infection then renames it back                                                             |
| 1260             | 1260  | (VB 199003) First poly; anti-debug                                                                                                                                                        |
| Proud            | 1302  | (VB 199012)                                                                                                                                                                               |
| Barrotes         | 1310  | On Jan 5th draws vertical bars across the display then overwrites the MBR — system unbootable on next reboot                                                                              |
| Invol            | 1409  | Spreads via .SYS device drivers in CONFIG.SYS — goes resident before DOS finishes booting, before any AV can load                                                                         |
| V2P2             | 1426  | (VB 199011)                                                                                                                                                                               |
| Athens           | 1463  | Goes resident consuming zero memory — total and free RAM unaffected, completely invisible to CHKDSK                                                                                       |
| Datacrime II     | 1480  | (VB 199008)                                                                                                                                                                               |
| Attack           | 1501  | Hooks INT 13h (disk BIOS) in addition to INT 21h — infection proceeds even when INT 21h monitors are active                                                                               |
| Zero Bug         | 1536  | Stealth length-hiding + COMSPEC targeting; payload: a smiley face appears and eats all zero characters visible on screen                                                                  |
| Alabama          | 1560  | Goes resident without INT 27h/INT 21h AH=31h; after one hour silently swaps FAT entries so the user executes a different program than launched                                            |
| Caterpillar      | 1575  | (VB 199110) Armored                                                                                                                                                                       |
| Mix1             | 1618  | (VB 198912) After 6th infection: ball bounces on screen, garbles serial/parallel port output, permanently locks Num Lock on                                                               |
| Slovak           | 1673  | Non-resident polymorphic — mutation runs entirely within the infected file at execution time, no in-memory helper                                                                         |
| Cascade          | 1701  | First encrypted DOS virus; falling-characters screen payload; source of the encryption technique copied by countless successors                                                           |
| Zoid             | 1751  | Resident but hooks no interrupts whatsoever — standard interrupt-chain scanning finds nothing                                                                                             |
| Dark avenger     | 1800  | (VB 199002)                                                                                                                                                                               |
| Jerusalem        | 1808  | The archetypal Friday-the-13th .COM+.EXE resident infector; historically significant as one of the first widely studied complex DOS viruses and progenitor of a huge variant family       |
| dBASE            | 1864  | (VB 198912) Transposes bytes in open .DBF files, intercepts reads to restore them transparently via hidden BUG.DAT; after 90 days corruption becomes permanent                            |
| PcVrsDs          | 1898  | (VB 199104)                                                                                                                                                                               |
| Yankee 2         | 1961  | Plays Yankee Doodle on the PC speaker each time it successfully infects a new file                                                                                                        |
| Smiley           | 1987  | Split architecture: non-resident replication engine + separate resident portion installed only to drive the screen effect                                                                 |
| Crusher          | 2048  | EXE infector that also infects the MBR, keeping the boot-sector copy unencrypted as a separate stash                                                                                      |
| Fu Manchu        | 2086  | Intercepts the keyboard buffer and inserts live derogatory commentary about named politicians — payload affects anything reading keyboard input                                           |
| 2100             | 2100  | (VB 199108)                                                                                                                                                                               |
| Silly Willy      | 2268  | Animated face claims to format the hard disk (it doesn't), then actually attempts to format the A: floppy — bait-and-switch payload                                                       |
| Casino           | 2332  | (VB 199103) On trigger dates presents a slot-machine game: if the user loses, writes back a corrupted FAT — hostage mechanic                                                              |
| Mayak            | 2339  | Reads C:\CONFIG.SYS to identify loaded device drivers, infects those .SYS files first, then goes dormant until reboot                                                                     |
| Flip             | 2343  | (VB 199009) Multipartite (file+MBR+boot) that only spreads from .EXE, never .COM or boot; on the 2nd of any month 16:00–16:59 horizontally flips the EGA/VGA display                      |
| Miky             | 2350  | Randomly rotates the entire screen to the right with character wraparound; also causes one lost FAT cluster per infected file                                                             |
| Haifa            | 2351  | Appends encrypted text to any .DOC file opened while resident; variable-length encryption makes two infected copies of the same file differ in size                                       |
| Tequila          | 2400  | (VB 199106)                                                                                                                                                                               |
| Maltese Amoeba   | 2504  | (VB 199112)                                                                                                                                                                               |
| Uruguay          | 2552  | Very complex poly; tunneling on both INT 13 and INT 21 — memory mapping tools report no hooks at all                                                                                      |
| Lexotran         | 2708  | No constant body (4)                                                                                                                                                                      |
| Bizarre          | 2716  | Belgian polymorphic fast infector of .COM and .SYS; changes infected files' directory year to the 1950s and makes CHKDSK report fake allocation errors                                    |
| Oropax           | 2756  | Plays three distinct tunes on the speaker at 7-minute intervals; forces infected file lengths to always be divisible by 51 as infection marker                                            |
| Liberty          | 2857  | (VB 199110)                                                                                                                                                                               |
| Invisible Man    | 2926  | Full stealth: hooks INT 21 to hide file length increases, hides its own memory block, and patches the MCB chain to conceal its TSR presence                                               |
| Pogue            | 2973  | Assembles itself from code fragments of four existing viruses; unencrypted copies are misidentified as one of those four by scanners                                                      |
| Yankeedoodle     | 3000+ | Based on Vacsina; v33+: self-correcting code; v50+: protected mode                                                                                                                        |
| Plastique        | 3012  | Randomly either slows the system to 50% speed or emits bomb noises from the speaker; one variant inverts the trigger window                                                               |
| Got-You          | 3052  | Jan–Jun silent replication; Jul–Dec activates with randomized payloads: redirecting network printers, printing screen, disabling last drive letter, creating hidden file of random memory |
| Traceback        | 3066  | Stores the infecting file's directory path inside each victim, creating a traceable forensic chain; after Dec 28 1988 produces a Cascade-style screen effect every hour                   |
| Joshi            | 3072  | (VB 199012)                                                                                                                                                                               |
| SVC              | 3100+ | (VB 199112)                                                                                                                                                                               |
| Storyteller      | 3184  | Each run of any infected program reinstalls a fresh copy in memory — many infected programs eventually exhaust all 640K; occasionally displays a children's story scene                   |
| MACHOSOFT        | 3500  | (VB 199105) SYSLOCK variant                                                                                                                                                               |
| One Half         | 3544  | Multipartite full-stealth MBR+file; embeds encrypted list of AV tool names suggesting active evasion by name-matching                                                                     |
| Andre            | 3568  | Polymorphic; hooks so stealthily no interrupt appears redirected; also converts infected .EXE files to .COM structure internally                                                          |
| Fish             | 3584  | Survives CTRL-ALT-DEL; continuously re-encrypts itself in memory; forces a warm reboot if it can't hook INT 13 on first run                                                               |
| Groove           | 3646  | DAME-polymorphic retrovirus that explicitly deletes data files of six named AV products                                                                                                   |
| Spanish Telecom  | 3700  | (VB 199101)                                                                                                                                                                               |
| Itavir           | 3880  | After 24h uptime writes values 0–255 to every I/O port sequentially — corrupts peripherals, causes monitors to hiss, corrupts the boot sector                                             |
| Tremor           | 4000  | Retrovirus; relocates bulk of code to upper/extended memory; marks infection by adding 100 to the year field of the file date                                                             |
| 4096 (Frodo)     | 4096  | (VB 199005) Full stealth from Israel; silently cross-links files via FAT manipulation, making damage look like hardware failure rather than infection                                     |
| Commander bomber | 4096  | Inserts in the middle of the host                                                                                                                                                         |
| Invader          | 4096  | Plays a melody after 30 minutes resident; if the user presses CTRL-ALT-DEL to escape, overwrites the first hard disk track as punishment                                                  |
| Music Bug        | 4096  | (VB 199111)                                                                                                                                                                               |
| Sentinel         | 4625  | Distributed with its full Turbo Pascal source code attached — one of the earliest documented open-source viruses                                                                          |
| Dreamer          | 4808  | Size-stealth infector; after 15 minutes resident repeatedly speaks 'Hitler!' through the PC speaker until the system hangs                                                                |
| TMC              | 4835  | No constant body (2)                                                                                                                                                                      |
| Ply              | 5175  | No constant body (1)                                                                                                                                                                      |
| RDA.Fighter      | 5871  | (VB 199712)                                                                                                                                                                               |
| Yap              | 6258  | Holding Alt spawns animated bugs that eat screen contents; releasing Alt restores the display — reversible interactive visual attack                                                      |
| Zhengxi          | 7168  | (VB 199604) Very complex poly                                                                                                                                                             |
| Whale            | 9216  | (VB 199011) Multilayer re-encryption in memory, on-the-fly disinfection during COPY, simulated warm reboots, keyboard lockout if a debugger is detected                                   |
| SSR              | 11260 | (VB 199607)                                                                                                                                                                               |

Engines:

| Name | Notes                                         |
| ---- | --------------------------------------------- |
| ZCME | No constant body (3)                          |
| ACG  | (VB 199907) Metamorphic engine (written in C) |
| SMEG | Complex poly engine                           |
