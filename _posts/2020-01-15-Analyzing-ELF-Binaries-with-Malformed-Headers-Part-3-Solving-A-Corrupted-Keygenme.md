---
layout: post
title: Analyzing ELF Binaries with Malformed Headers Part 3 - Automatically Solving a Corrupted Keygenme with angr
tags: [angr, cutter, emulation, symbolic-execution, crackme, keygenme, reverse-engineering, header-mangling, ELF, AMD64]
author-id: julian
---

Crackme-style challenge programs often incorporate techniques designed to resist or slow down analysis; one such technique - quite familiar by now -
is corruption of the header of the binary, but many other techniques exist as well. For example, a program may be designed to deliberately perform overly
complex operations that are difficult for a human to follow during analysis, increasing the time required
to sufficiently comprehend program behavior. The keygenme binary that will be analyzed here is an example of this. It will be 
demonstrated that in this case, a viable approach to overcoming the challenge posed for analysis by some of the program's rather opaque internal 
operations is to devise a method that will automatically generate inputs that solve the binary using the angr binary analysis toolkit.


### Overview

The following will be discussed:

 - how to repair a corrupted ELF header such that tools such as [angr](https://github.com/angr/angr) or gdb can be used to interface with the binary
 - using [Cutter](https://cutter.re/) to analyze program flow-of-control and understand program behavior
 - how to automatically generate correct inputs to the program with angr using symbolic variables and files, file system emulation, program state space exploration, 
   and constraint solving

### Prerequisites

 - a basic understanding of some of angr's underlying principles and concepts, such as what symbolic variables and constraint solving are 
 - a basic understanding of the various components of angr that are used to load and analyze the binary e.g. program states and simulation managers

All of these are explained in the "Core Concepts" section of the [angr documentation](https://docs.angr.io/). Various example programs leveraging angr
to solve challenge programs can be found in the documentation as well in the [Examples](https://docs.angr.io/examples) section.


# Summary

Rather than first sequentially walking through the steps taken to solve the challenge in fine detail and then presenting the results at the very end, a
relatively concise overview will be provided first, with the details discussed afterward. The analysis may be easier to follow if a clear path to 
a solution is presented beforehand.

### The binary:

 - The challenge page can be found on [crackmes.one](https://crackmes.one/crackme/5d7c66d833c5d46f00e2c45b).
 - Download link:
   - https://crackmes.one/static/crackme/5d7c66d833c5d46f00e2c45b.zip
   - password to unzip the zip archive: `crackmes.one`

### Challenge parameters:

>If you can take a problem and wrangle it into a form where it has defined and tractable inputs and outputs,
you can absolutely use angr to achieve your goals, given that these goals involve analyzing binaries. [1]

This is exactly the case here.

A common form of crackme program is one in which a specific input to the program (such as a secret password or numeric value) solves the challenge, 
and the goal of the analysis is to discover what that input is.
The classic IOLI challenges[3] are examples of this type of design. 
However, since the program we are dealing with here is a *keygenme*, rather than a single correct input, there is actually a large set of inputs 
that will solve the challenge. Therefore, the goal is slightly different - the aim is to understand the logic of the program such that we can devise 
a method of generating multiple inputs that are part of the set of solutions. In our case, the set of solutions consists of the intersection of 2 subsets:

 - the set of strings that are valid usernames
 - the set of strings that are valid passwords  

With the right constraints applied, angr will compute solutions automatically; our task is to interface angr with the binary such that the necessary constraints
are discovered.

The binary is listed as a level 3 challenge ("medium") on a scale of 1 to 6, where 6 is maximum difficulty ("insane"). 
To get the `G00d P422w0rd` message, a correct username and password must be passed as arguments on the command line to the program. 
While the username is passed as a string as the first argument, the password must be in a file, and the path to the file  passed as the second argument:

```
$ ./keygenme 
Usage ./keygenme <username> <filepath>
```

**Important**: If a text editor is used to write a password to the input file, 
or if `echo PASSWORD_STRING > INPUT_FILE.txt` is used to pipe the password string into the file, it will usually be evaluated as *incorrect* even if it is 
correct, or cause the program to segfault, due to a trailing `0x0a` byte being included after the string. It does not seem like the author of the crackme took 
this into consideration, and this particular problem resulted in several hours being wasted trying to determine why valid passwords were being rejected as invalid.

To guarantee that the submitted password is correctly parsed by the program, the following method can be used:

```shell
$ python -c 'with open("INPUT_FILE.txt", "w") as f: f.write("PASSWORD_STRING")'
``` 

It should also be noted that the messages indicating success and failure - `G00d P422w0rd` and `B4d P422w0RD` - are 
written to the file containing the password rather than to stdout. 

In order to use angr to automatically generate valid usernames and passwords that solve the challenge, the following must be known:
 - what form the inputs must take in order to produce the desired output:
   - constraints on the length and format of the username
   - constraints on the length and format of the password
   - the location of the code that outputs the message indicating that the inputs were correct, as well as the format of this message
 - the path that must be taken through the program logic to reach the target code that writes the desired output, as well as which parts of the program to avoid
 - how to successfully interface angr with the binary, such that the input is symbolic rather than concrete. Since the password is in a file passed
   as an argument on the command line, this is somewhat complicated.


Cutter was used to perform the initial analysis. In particular, control-flow graphs of various functions were analyzed to understand how the program worked overall.

Here is a simple summary of the program's flow of control. The red path leads to the function which outputs `G00d P422w0rd`, 
which indicates the inputs were correct, so this is the target code for angr to reach when exploring paths through the binary.

<img src="{{site.baseurl}}/assets/img/2020-1-16-program-flow/program_flow.gv.png">

### Solutions: 

After determining the length and format requirements for usernames and passwords, as well as which path to take throught the program logic to arrive at
the code responsible for indicating success, angr can be directed to explore the state space of the program by emulating it symbolically, discovering the conditions
necessary to reach the target code along the way. This information can then used by a constraint solver to generate username and password strings such that if those
strings are entered as input, the success message will be written as output (in this case to the password file, not stdout). 
Here is an example of what finding a solution with angr can look like:

```shell
$ ./autosolve_keygenme.py 
[ 23:12:36.438534 ] Exploration started...
WARNING | 2020-01-15 23:14:59,613 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-01-15 23:14:59,613 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-01-15 23:14:59,613 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-01-15 23:14:59,613 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-01-15 23:14:59,613 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-01-15 23:14:59,613 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0000 with 204 unconstrained bytes referenced from 0x1000220 (fopen+0x0 in extern-address space (0x220))
WARNING | 2020-01-15 23:15:10,161 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0001040 with 240 unconstrained bytes referenced from 0x1000218 (__printf_chk+0x0 in extern-address space (0x218))
[ 23:17:30.706189 ] Finished...
[ 23:17:30.706266 ] Computing valid username... 
[ 23:17:30.706540 ] Username: eGMu3oCgcS
[ 23:17:30.706579 ] Computing valid password... 
[ 23:17:30.707143 ] Password: NZKIPPOPQSMSACP
[ 23:17:30.707182 ] Checking...
[ 23:17:30.789811 ] NZKIPPOPQSMSACP:  'G00d P422w0rd\n\x00'
``` 
After running for approximately 5 minutes (on not very good hardware) a valid username and password are found, resulting in the program outputting the message
that indicates a solution was found.

Here is the program producing the above output:

<script src="https://gist.github.com/BinaryResearch/9a06c85b4b333caf635f7a1e26857f1c.js"></script>

The purpose of this script is to demonstrate the viability of the approach taken here to solving the challenge and represents a realization of the entire sequence
of steps required to automatically find solutions with angr. 

An explanation of the various components of this script is given in the "Analysis" section. 
I will state here though that the most conceptually difficult part of the challenge was determining how to use angr to read a symbolic variable 
representing the password from inside a symbolic file. This is handled in lines 29 - 35 in the script. The trick is to pass the name of the symbolic file as an 
argument when creating the initial program state instead of the pathname of the real file, and then insert this symbolic file into the emulated filesystem
prior to emulation. When angr  
emulates the program, the symbolic file will be opened instead of the real password file. The symbolic variable representing the variable will then be read and
eventually have solutions computed for it.

The file containing the password is called "key.txt", as stated in the code comments. The `G00d P422w0rd` and `B4d P422w0RD` messages are written to this same file,
so this file is checked after the username and password are computed and the keygenme is run with these as inputs to verify that `G00d P422w0rd` has been written.
On rare occasions, a solution will not be found. 
If this is the case, the script can simply be run again; angr computes a different username and password each time.
 
The script can be modified to compute more than just one username and password if so desired. 
A password length of 15 characters was arbitrarily chosen - any length from 4 through 49 should work. Computing shorter passwords is 
faster and consumes less RAM.

Here is another example solution, in which 10 valid 8-character passwords are computed for a known good username:

```shell
$ ./find_valid_passwords.py 
[ 11:37:54.515668 ] Exploration started...
WARNING | 2020-01-17 11:37:55,618 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-01-17 11:37:55,618 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-01-17 11:37:55,618 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-01-17 11:37:55,618 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-01-17 11:37:55,618 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-01-17 11:37:55,618 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0000 with 204 unconstrained bytes referenced from 0x1000220 (fopen+0x0 in extern-address space (0x220))
WARNING | 2020-01-17 11:38:00,187 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0001039 with 247 unconstrained bytes referenced from 0x1000218 (__printf_chk+0x0 in extern-address space (0x218))
[ 11:42:11.144212 ] Finished...
[ 11:42:11.144274 ] Computing valid passwords... 
[ 11:43:11.670569 ] Finished. Checking passwords for username 24T5JFN9fU:
[ + ] AZWPEPEM:  'G00d P422w0rd\n\x00'
[ + ] AZWPEPMY:  'G00d P422w0rd\n\x00'
[ + ] AZWPEPMU:  'G00d P422w0rd\n\x00'
[ + ] AZWPEPEU:  'G00d P422w0rd\n\x00'
[ + ] AZWPEPEA:  'G00d P422w0rd\n\x00'
[ + ] CZCVWPCH:  'G00d P422w0rd\n\x00'
[ + ] AZWPEPMI:  'G00d P422w0rd\n\x00'
[ + ] EFGPALED:  'G00d P422w0rd\n\x00'
[ + ] OLCTKRUD:  'G00d P422w0rd\n\x00'
[ + ] AZWPEPEE:  'G00d P422w0rd\n\x00'
[ 11:43:12.312680 ] Finished.
```

The code that produced this output will be discussed below in the "Analysis" section.

The summary concludes here.

<hr>

# Analysis

Contents:

  1. Dealing with the corrupt ELF header
     - Recovering the correct values
     - Zeroing out the corrupted fields
  2. Analyzing the program with Cutter
     - Using angr to automatically generate valid usernames based on the information in main()
  3. Using angr to automatically generate valid passwords for a given valid username
  4. Examples of the keygenme mishandling input

## 1) Dealing with the corrupted header 

The binary is a Position Independent Executable (PIE). The crackme author has corrupted some of the fields having to do with sections:

```shell
$ readelf -h keygenme 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1320
  Start of program headers:          64 (bytes into file)
  Start of section headers:          65535 (bytes into file)         <----------- e_shoff
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           64 (bytes)
  Number of section headers:         65535                           <----------- e_shnum
  Section header string table index: 65535 <corrupt: out of range>   <----------- e_shstrndx
readelf: Error: Reading 4194240 bytes extends past end of file for section headers
readelf: Error: Reading 14312 bytes extends past end of file for dynamic string table
```

The corruption seen here is identical to the corruption induced by Julien Voisin's 
[elfscrewer](https://dustri.org/b/screwing-elf-header-for-fun-and-profit.html) tool. This is significant because this technique does not
involve stripping section information from the binary, meaning if the ELF header fields are changed back to the correct values, section information
can be used again. Tools such as gdb rely on intact section information in order to parse and load a binary.


CLE, the loader used by angr, is not able to load the binary due the invalid values in these fields:

```shell
      .
 < backtrace snipped >
      .
  File "/usr/local/lib/python3.6/dist-packages/elftools/elf/elffile.py", line 81, in __init__
    self._file_stringtable_section = self._get_file_stringtable()
  File "/usr/local/lib/python3.6/dist-packages/elftools/elf/elffile.py", line 573, in _get_file_stringtable
    header=self._get_section_header(stringtable_section_num),
  File "/usr/local/lib/python3.6/dist-packages/elftools/elf/elffile.py", line 468, in _get_section_header
    stream_pos=self._section_offset(n))
  File "/usr/local/lib/python3.6/dist-packages/elftools/common/utils.py", line 42, in struct_parse
    raise ELFParseError(str(e))
elftools.common.exceptions.ELFParseError: expected 4, found 0
```

There are 2 approaches that can be taken to addressing this:
  1. Recovering the correct values 
  2. Zeroing out the corrupted fields

### Recovering the correct values

The section header table is appended to the end of the file after the very last section, which is `.shstrtab` - the section header string table:

```
00002fe0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00003000  00 00 00 00 00 00 00 00  08 40 00 00 00 00 00 00  |.........@......|
00003010  47 43 43 3a 20 28 55 62  75 6e 74 75 20 38 2e 33  |GCC: (Ubuntu 8.3|        
00003020  2e 30 2d 36 75 62 75 6e  74 75 31 29 20 38 2e 33  |.0-6ubuntu1) 8.3| <-----\          
00003030  2e 30 00 00 2e 73 68 73  74 72 74 61 62 00 2e 69  |.0...shstrtab..i|       |
00003040  6e 74 65 72 70 00 2e 6e  6f 74 65 2e 67 6e 75 2e  |nterp..note.gnu.|       |  
00003050  62 75 69 6c 64 2d 69 64  00 2e 6e 6f 74 65 2e 41  |build-id..note.A|       |      
00003060  42 49 2d 74 61 67 00 2e  67 6e 75 2e 68 61 73 68  |BI-tag..gnu.hash|       |
00003070  00 2e 64 79 6e 73 79 6d  00 2e 64 79 6e 73 74 72  |..dynsym..dynstr|       |
00003080  00 2e 67 6e 75 2e 76 65  72 73 69 6f 6e 00 2e 67  |..gnu.version..g|       \
00003090  6e 75 2e 76 65 72 73 69  6f 6e 5f 72 00 2e 72 65  |nu.version_r..re|         .shstrtab
000030a0  6c 61 2e 64 79 6e 00 2e  72 65 6c 61 2e 70 6c 74  |la.dyn..rela.plt|       /
000030b0  00 2e 69 6e 69 74 00 2e  70 6c 74 2e 67 6f 74 00  |..init..plt.got.|       |
000030c0  2e 74 65 78 74 00 2e 66  69 6e 69 00 2e 72 6f 64  |.text..fini..rod|       |
000030d0  61 74 61 00 2e 65 68 5f  66 72 61 6d 65 5f 68 64  |ata..eh_frame_hd|       |
000030e0  72 00 2e 65 68 5f 66 72  61 6d 65 00 2e 69 6e 69  |r..eh_frame..ini|       |
000030f0  74 5f 61 72 72 61 79 00  2e 66 69 6e 69 5f 61 72  |t_array..fini_ar|       |
00003100  72 61 79 00 2e 64 79 6e  61 6d 69 63 00 2e 64 61  |ray..dynamic..da|       |
00003110  74 61 00 2e 62 73 73 00  2e 63 6f 6d 6d 65 6e 74  |ta..bss..comment|  <----/
00003120  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................| <------------------- section header table
*                                                                                                    starts at offset
00003160  00 00 00 00 00 00 00 00  0b 00 00 00 01 00 00 00  |................| <---------\            0x00003128
00003170  02 00 00 00 00 00 00 00  a8 02 00 00 00 00 00 00  |................|            \-------- the space between 0x0b
00003180  a8 02 00 00 00 00 00 00  1c 00 00 00 00 00 00 00  |................|                      and the beginning of the 
00003190  00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |................|                      section header table is 
000031a0  00 00 00 00 00 00 00 00  13 00 00 00 07 00 00 00  |................|                      0x40 (64) bytes
000031b0  02 00 00 00 00 00 00 00  c4 02 00 00 00 00 00 00  |................|
``` 

A tool called lepton[3] can be used to repair the ELF header:

<script src="https://gist.github.com/BinaryResearch/76f4747734a0feb06e0ba5739bdc2ba7.js"></script>

ELF header after repair:

```shell
$ readelf -h fixed_keygenme 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1320
  Start of program headers:          64 (bytes into file)
  Start of section headers:          12584 (bytes into file)  <----- e_shoff
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           64 (bytes)
  Number of section headers:         27                       <----- e_shnum
  Section header string table index: 26                       <----- e_shstrndx
```

Section information can now be displayed:

```
$ readelf -SW fixed_keygenme 
There are 27 section headers, starting at offset 0x3128:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000000000002a8 0002a8 00001c 00   A  0   0  1
  [ 2] .note.gnu.build-id NOTE            00000000000002c4 0002c4 000024 00   A  0   0  4
  [ 3] .note.ABI-tag     NOTE            00000000000002e8 0002e8 000020 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        0000000000000308 000308 000030 00   A  5   0  8
  [ 5] .dynsym           DYNSYM          0000000000000338 000338 000240 18   A  6   1  8
  [ 6] .dynstr           STRTAB          0000000000000578 000578 00012d 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          00000000000006a6 0006a6 000030 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         00000000000006d8 0006d8 000050 00   A  6   1  8
  [ 9] .rela.dyn         RELA            0000000000000728 000728 0000f0 18   A  5   0  8
  [10] .rela.plt         RELA            0000000000000818 000818 000180 18  AI  5  22  8
  [11] .init             PROGBITS        0000000000001000 001000 000017 00  AX  0   0  4
  [12] .plt              PROGBITS        0000000000001020 001020 000110 10  AX  0   0 16
  [13] .plt.got          PROGBITS        0000000000001130 001130 000008 08  AX  0   0  8
  [14] .text             PROGBITS        0000000000001140 001140 000db1 00  AX  0   0 16
  [15] .fini             PROGBITS        0000000000001ef4 001ef4 000009 00  AX  0   0  4
  [16] .rodata           PROGBITS        0000000000002000 002000 000310 00   A  0   0 16
  [17] .eh_frame_hdr     PROGBITS        0000000000002310 002310 00007c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        0000000000002390 002390 000268 00   A  0   0  8
  [19] .init_array       INIT_ARRAY      0000000000003d40 002d40 000008 08  WA  0   0  8
  [20] .fini_array       FINI_ARRAY      0000000000003d48 002d48 000008 08  WA  0   0  8
  [21] .dynamic          DYNAMIC         0000000000003d50 002d50 0001f0 10  WA  6   0  8
  [22] .got              PROGBITS        0000000000003f40 002f40 0000c0 08  WA  0   0  8
  [23] .data             PROGBITS        0000000000004000 003000 000010 00  WA  0   0  8
  [24] .bss              NOBITS          0000000000004020 003010 000030 00  WA  0   0 32
  [25] .comment          PROGBITS        0000000000000000 003010 000023 01  MS  0   0  1
  [26] .shstrtab         STRTAB          0000000000000000 003033 0000ee 00      0   0  1
```

Since the section information is now present and correct, gdb can be used to debug the binary. This approach is not taken here, because relying on
section information is for babies and using gdb to analyze this program is very inefficient compared with using Cutter, which is vastly more powerful
and its integrated debugger does not need section information to load the binary.


### Zeroing out the affected fields

angr can load the binary without any problems after the corrupted fields are zeroed out. Patching the header can be done
with `lepton`, but this snippet also does the job:

```python
with open("keygenme", "rb+") as f:
    f.seek(0x28)
    f.write(b'\x00\x00')
    f.seek(0x3a)
    f.write(b'\x00\x00\x00\x00\x00\x00')
```

After patch:

```
$ readelf -h keygenme 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1320
  Start of program headers:          64 (bytes into file)
  Start of section headers:          0 (bytes into file)   <--------- e_shoff
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           0 (bytes)
  Number of section headers:         0                     <--------- e_shnum
  Section header string table index: 0                     <--------- e_shstrndx
readelf: Error: Reading 14312 bytes extends past end of file for dynamic string table  <--- irrelevant
```

## 2. Analyzing the program with Cutter

Though the decompiler from Ghidra has been integrated with Cutter, it was not used in the analysis, since I did not find the decompiled code to be
particularly helpful. Some decompiled code will be included here to show why this was the case. I found that reading control-flow graphs of disassembled functions 
was clearer and more suitable for the purpose of using angr to compute solutions.

### main()

Here the bytes of the username are iterated over and checked (basic blocks `0x000011c7` - `0x00001255`). 
 - 10 bytes are checked in total, which tells us the expected length of the username. 
 - If the comparisons all succeed, `fcn.0x00001a00` is called at offset `0x00001277`, which reads the content of the password file.

<img src="{{site.baseurl}}/assets/img/2020-1-16-program-flow/graph-main.png">

This is already enough information to use angr to compute valid usernames, since we now know the length of the username, as well as the path that is taken 
through `main` to `fcn.00001a00` if the username is valid.

 - target address: 
   - `0x00001264` - this offset is for an instruction that is executed after all the checks of the bytes in the username have succeeded
 - avoid: 
   - `0x000012c2` - argc != 3
   - `0x000012ff` - bad username
 - skip: 
   - instructions in range `0x00001166` to `0x00001177`. The code in this range calls a function which prints some statements by the crackme author. 
     It has no bearing on the rest of the program, so it can be skipped to save time

The comments in the script below explain the code.

<script src="https://gist.github.com/BinaryResearch/70a69e651034eed27fb14d129e8269f1.js"></script>

Output:

```
$ ./find_valid_usernames.py 
[ 14:05:21.280678 ] Exploration started...
[ 14:07:51.566523 ] Finished...
[ 14:07:51.566622 ] Computing valid usernames... 
[ 14:07:59.849391 ] Complete. Writing to file...
AyAAS9rjDV
Z36HKLfBA3
Z36HiLfBA3
GhMmh2DnQq
GhMmh2DnQX
          .
 < output of 95 more usernames snipped>
          .
```
 


### fcn.00001a00

This function checks if the password file can be read, and if so reads the content of the file and performs checks of the length and byte values.
The string must be shorter than 50 characters (check performed at offset `0x00001a9b`) and must not contain special characters such as {}, [], (), -, etc.

Looking at the CFG of this function makes it straightforward to identify what branches in flow-of-control to avoid, which is very
useful to know if the plan is to use angr to explore the binary via symbolic execution. In a nutshell, we want to avoid basic blocks which perform the 
following operations: 

 - write 0 to `[r12]`, `[r12 + 0x18]` and `[r12 + 8]`
 - call `exit`, `fclose`, `free`, or `__stack_check_fail`

If all is well, this function returns to the main function.

<img src="{{site.baseurl}}/assets/img/2020-1-16-program-flow/graph-fcn_00001a00.png">

### fcn.0001bb0

Some of the operations performed in here were rather hard to follow, especially the code in very large basic block at `0x00001ce8`. 

<img src="{{site.baseurl}}/assets/img/2020-1-16-program-flow/graph-fcn_00001bb0.png">

The decompiled code for this function also was not particularly helpful:

```c
void fcn.00001bb0(int64_t arg1, int64_t arg2)
{
    uint8_t *puVar1;
    uint8_t *puVar2;
    uint8_t uVar3;
    uint32_t uVar4;
    uint64_t uVar5;
    uint64_t uVar6;
    uint64_t uVar7;
    uint32_t uVar8;
    uint8_t uVar9;
    uint32_t uVar10;
    uint8_t uVar11;
    uint8_t uVar12;
    uint8_t uVar13;
    uint8_t uVar14;
    uint32_t uVar15;
    uint8_t uVar16;
    int64_t iVar17;
    uint8_t uVar18;
    int64_t iVar19;
    uint8_t uVar20;
    uint64_t uVar21;
    int64_t in_XMM0_Qa;
    undefined8 in_XMM1_Qa;
    undefined8 in_XMM2_Qa;
    undefined8 in_XMM3_Qa;
    undefined8 in_XMM4_Qa;
    undefined8 in_XMM5_Qa;
    undefined8 in_XMM6_Qa;
    undefined8 in_XMM7_Qa;
    uint64_t uStack104;
    
    uVar21 = *(uint64_t *)(arg1 + 8);
    uVar7 = *(uint64_t *)(arg2 + 8);
    if (uVar21 == uVar7) {
        puVar1 = *(uint8_t **)arg2;
        puVar2 = *(uint8_t **)arg1;
        if (uVar21 == 0) {
code_r0x00001e88:
    // WARNING: Subroutine does not return
            fcn.00001830(in_XMM0_Qa);
        }
        if (*puVar1 == *puVar2) {
            uVar7 = 0;
            do {
                uVar7 = (uint64_t)((int32_t)uVar7 + 1);
                if (uVar21 <= uVar7) {
                    if (uVar21 == uVar7) goto code_r0x00001e88;
                    break;
                }
            } while (puVar2[uVar7] == puVar1[uVar7]);
        }
        uStack104 = 0;
        iVar17 = 0;
        uVar21 = 1;
        do {
            uVar3 = puVar2[iVar17];
            uVar11 = (*puVar1 ^ uVar3) & 0xf;
            uVar12 = (puVar1[1] ^ uVar3 ^ 1) & 0xf;
            uVar20 = (puVar1[2] ^ uVar3 ^ 2) & 0xf;
            uVar18 = (puVar1[3] ^ uVar3 ^ 3) & 0xf;
            uVar16 = (puVar1[4] ^ uVar3 ^ 4) & 0xf;
            uVar14 = (puVar1[5] ^ uVar3 ^ 5) & 0xf;
            uVar15 = (int32_t)(char)uVar3 + (uint32_t)iVar17 ^ (uint32_t)iVar17;
            uVar13 = (puVar1[6] ^ uVar3 ^ 6) & 0xf;
            uVar9 = (puVar1[7] ^ uVar3 ^ 7) & 0xf;
            uVar3 = (uVar3 ^ puVar1[8] ^ 8) & 0xf;
            iVar17 = iVar17 + 1;
            uStack104 = uStack104 +
                        (int64_t)(char)uVar9 +
                        (int64_t)(char)uVar14 +
                        (int64_t)(char)uVar18 + (int64_t)(char)uVar20 + (int64_t)(char)uVar12 + (int64_t)(char)uVar11 +
                        (int64_t)(char)uVar16 + (int64_t)(char)uVar13 + (int64_t)(char)uVar3;
            uVar21 = uVar21 * (uint64_t)((int32_t)(char)uVar12 | uVar15) * (uint64_t)((int32_t)(char)uVar20 | uVar15) *
                              (uint64_t)((int32_t)(char)uVar11 | uVar15) * (uint64_t)((int32_t)(char)uVar18 | uVar15) *
                              (uint64_t)((int32_t)(char)uVar16 | uVar15) * (uint64_t)((int32_t)(char)uVar14 | uVar15) *
                              (uint64_t)((int32_t)(char)uVar13 | uVar15) * (uint64_t)((int32_t)(char)uVar9 | uVar15) *
                              (uint64_t)((int32_t)(char)uVar3 | uVar15);
        } while (iVar17 != 10);
        if (((uVar21 % uStack104) * 5 & 0xf) == 0) {
code_r0x00001e3d:
    // WARNING: Subroutine does not return
            fcn.00001560(in_XMM0_Qa, in_XMM1_Qa, in_XMM2_Qa, in_XMM3_Qa, in_XMM4_Qa, in_XMM5_Qa, in_XMM6_Qa, in_XMM7_Qa
                         , (char **)arg2);
        }
    } else {
        if (uVar7 != 0) {
            uVar6 = 0;
            iVar19 = 1;
            iVar17 = 0;
            do {
                if (uVar21 != 0) {
                    uVar5 = 0;
                    uVar15 = (int32_t)*(char *)(*(int64_t *)arg2 + uVar6);
                    do {
                        uVar8 = (uint32_t)uVar5;
                        uVar4 = (int32_t)*(char *)(*(int64_t *)arg1 + uVar5) +
                                ((int32_t)*(char *)(*(int64_t *)arg2 + uVar6) ^ uVar8) & 0xf;
                        iVar17 = iVar17 + (uint64_t)(uVar4 * 2);
                        uVar10 = uVar8 ^ (uint32_t)uVar6 | uVar15;
                        uVar15 = uVar15 + 1;
                        iVar19 = iVar19 * (uint64_t)(uVar4 | uVar10);
                        uVar5 = (uint64_t)(uVar8 + 1);
                    } while (uVar5 < uVar21);
                }
                uVar6 = (uint64_t)((uint32_t)uVar6 + 1);
            } while (uVar6 < uVar7);
            uVar21 = (uint64_t)(iVar19 - iVar17) % (iVar17 + iVar19);
            if (((int32_t)(9 % (uint64_t)((uint32_t)uVar21 & 0xf)) == 0) && ((uVar21 & 0xf) != 0))
            goto code_r0x00001e3d;
        }
    }
    // WARNING: Subroutine does not return
    fcn.000016d0(in_XMM0_Qa, in_XMM1_Qa, in_XMM2_Qa, in_XMM3_Qa, in_XMM4_Qa, in_XMM5_Qa, in_XMM6_Qa, in_XMM7_Qa, 
                 (char **)arg2);
}
```

Fortunately, it is not necessary to understand everything that is happening here. In fact, there is no need to analyze this complicated code at all -
we only need to find the path to the code that prints `G00d P422w0rd`.

What we do know:

 - This function is called from `main` after `fcn.00001a00` returns. 
 - As indicated in the decompilation, this function does not return. This is clear from not just from the CFG of `main` but
   also from its own CFG displayed above
 - Rather than return, 1 of 3 functions is called:
   - `fcn.00001830`
   - `fcn.00001560`
   - `fcn.000016d0` 
 - Looking at the CFG of the current function, we can see that `fcn.00001560` and `fcn.000016d0` take a pointer to a file name as an argument but 
   `fcn.00001830` does not. This eliminates `fcn.00001830` from consideration as a function containing the code that writes `G00d P422w0rd` to the password file.

### fcn.000016d0

After looking at `fcn.00001560` and `fcn.000016d0` using Cutter, we see that `fwrite` is called, as well as the string `[+] Check your file`.
This indicates that one of these two functions must write `G00d P422w0rd` to the password file, but we don't yet know which one.

<img src="{{site.baseurl}}/assets/img/2020-1-16-program-flow/graph-fcn_000016d0.png">

After we choose one of the username strings that was computed by the angr script earlier -  `Z36HiLfBA3`, for example - and create a file called 
"key.txt" containing test input in the form of the string "AAAA" to use as our password file, we can fire up Cutter's debugger.

When asked for command line arguments, we will enter `Z36HiLfBA3` and `key.txt` like so:

<img src="{{site.baseurl}}/assets/img/2020-1-16-program-flow/BinaryNewbie-keygenme-cutter-debugger-cmdline-args-cropped.png">


Then we will set 2 breakpoints: one where `fwrite` is called in `fcn.00001560` and one where `fwrite` is called in `fcn.000016d0`. A pointer to 
the output that be written to the password file will be contained in the `RDI` register once either breakpoint is hit:

<img src="{{site.baseurl}}/assets/img/2020-1-16-program-flow/BinaryNewbie-keygenme-fcn.000016d0-failure-key-output-cropped.png">

The string pointed to in this case is `B4d P422w0rd`; therefore, the target code printing `G00d P422w0rd` lies in the other function, `fcn.00001560`.
Now we have all the information we need in order to use angr to compute usernames and passwords in a single program, thereby automatically generating solutions
for us. Example code accomplishing this was provided in the "Summary" section above, in the `autosolve_keygenme.py` script.

## 3. Using angr to generate valid passwords for a given valid username

Let's see what some passwords for the username `Z36HiLfBA3` look like:

```shell
$ ./find_valid_passwords.py 
[ 18:31:11.987510 ] Exploration started...
WARNING | 2020-01-17 18:31:13,136 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-01-17 18:31:13,136 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-01-17 18:31:13,136 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-01-17 18:31:13,136 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-01-17 18:31:13,136 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-01-17 18:31:13,137 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0000 with 204 unconstrained bytes referenced from 0x1000220 (fopen+0x0 in extern-address space (0x220))
WARNING | 2020-01-17 18:31:17,668 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0001039 with 247 unconstrained bytes referenced from 0x1000218 (__printf_chk+0x0 in extern-address space (0x218))
[ 18:35:10.435142 ] Finished...
[ 18:35:10.435242 ] Computing valid passwords... 
[ 18:36:06.310322 ] Finished. Checking passwords for username Z36HiLfBA3:
[ + ] QPUBKPAM:  'G00d P422w0rd\n\x00'
[ + ] KRWFOBEM:  'G00d P422w0rd\n\x00'
[ + ] KRWFOBEA:  'G00d P422w0rd\n\x00'
[ + ] YBYLYVWH:  'G00d P422w0rd\n\x00'
[ + ] KRWFOBEH:  'G00d P422w0rd\n\x00'
[ + ] KRWFOBEI:  'G00d P422w0rd\n\x00'
[ + ] APUBKPQE:  'G00d P422w0rd\n\x00'
[ + ] APUBKPAE:  'G00d P422w0rd\n\x00'
[ + ] QPUBKPAE:  'G00d P422w0rd\n\x00'
[ + ] KRWFOBEL:  'G00d P422w0rd\n\x00'
[ 18:36:07.466093 ] Finished.
```
We can manually verify that the results are correct:

<script id="asciicast-VqD4glRUDn1NuqVDpdIJ6Jppx" src="https://asciinema.org/a/VqD4glRUDn1NuqVDpdIJ6Jppx.js" async data-cols="150" data-rows="30" data-speed="3"></script>

Here is the code:

<script src="https://gist.github.com/BinaryResearch/1dabfcfd5bf9c8cc284976e6de0c5782.js"></script>


## 4. Examples of the keygenme mishandling input

The program can crash due to a segmentation fault if the password is piped into the file with the `echo` command. The username and password are the same as above: 

<script id="asciicast-HBfhNd58Fzrc3rD6zZj6KJg0u" src="https://asciinema.org/a/HBfhNd58Fzrc3rD6zZj6KJg0u.js" async data-cols="150" data-rows="30" data-speed="5"></script>

Another example - instead of segfaulting, the program outputs `B4d P422w0rd` first, then `G00d P422w0rd` next:

<script id="asciicast-XrmzVZTFJxWdwZh8A4V5FilFI" src="https://asciinema.org/a/XrmzVZTFJxWdwZh8A4V5FilFI.js" async data-cols="150" data-rows="30" data-speed="5"></script>

Dealing with this problem before the cause was found was rather frustrating. This behavior was observed with many different
correct username and password combinations.

# Conclusion

angr and Cutter are outstanding tools for reverse engineering and binary analysis. angr in particular is incredibly powerful, allowing us to automatically solve
this keygenme with just a few lines of code and approximately 5 minutes of running time, in spite of how complex some portions of the keygenme's code was. We could
essentially skip a great deal of the analysis that would have been required to solve the keygenme if we were to rely on a tool like gdb. 

# Links and References

1. [angr Documentation: Remarks](https://docs.angr.io/core-concepts/be_creative)
2. [IOLI crackmes](https://github.com/Maijin/Workshop2015/tree/master/IOLI-crackme/bin-linux)
3. [lepton](https://github.com/BinaryResearch/lepton)
