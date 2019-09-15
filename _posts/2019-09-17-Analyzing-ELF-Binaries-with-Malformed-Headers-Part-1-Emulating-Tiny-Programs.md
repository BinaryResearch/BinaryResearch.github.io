---
layout: post
title: Analyzing ELF Binaries with Malformed Headers Part 1 - Emulating Tiny Programs
tags: [emulation, unicorn-engine, capstone-engine, disassembly, reverse-engineering, anti-analysis, header-mangling, ELF, AMD64, x86-64]
author-id: julian
---

A simple but often effective method for complicating or preventing analysis of an ELF binary by many common tools (`gdb`, `readelf`, `pyelftools`, etc)
is mangling, damaging or otherwise manipulating values in the ELF header such that the tool parsing the header does so incorrectly, perhaps
even causing the tool to fail or crash. Common techniques include overlapping the program header(s) with the ELF header and writing 
garbage values to ELF header fields that are not read by the kernel when loading the binary into memory. In addition to some programs designed for criminal
purposes (e.g. the "mumblehard" family of malware programs), a few code-golf- and proof-of-concept-type programs have been created that employ these techniques. 
Examples of such programs include
Brian Raiter's "teensy" files and @netspooky's "golfclub" programs. In this post, it will be demonstrated how emulation can be used to easily trace the execution
of these types of binaries.

### Overview

The following will be discussed:
 - how header mangling works as an anti-analysis technique
 - how to use the Unicorn Engine to analyze binaries with malformed headers

Tools:
 - Capstone Engine
 - Unicorn Engine
 - Python3


# Header mangling

This technique has already been covered in depth elsewhere, mainly because criminal software has employed header mangling in the past, so the discussion
here will be brief. The main reason mangling the ELF header works to complicate analysis is that even though only a specific subset of the fields in the ELF header are 
read by the kernel when loading the program into memory, most ELF parsers do not parse the ELF header the way the kernel loader does 
and thus are prone to malfunction when reading unexpected or garbage values in fields not needed for creating the process image of the binary in memory. The most
typical examples of this are `gdb`, `objdump` and the rest of the `libbfd`-based binutils tools, which will not even read an object file unless its section 
information is present and intact.

The minimalist programs that push the limits of the least number of bytes a file can consist of and still execute successfully take advantage of the fact that not
all ELF header fields are needed for loading and executing the program and can therefore be used to contain code or other non-standard values - their entry point is often *inside* the ELF header. 
On the one hand, even though their purpose is not to complicate
analysis, these programs serve to highlight the limitations of many common tools designed to work with the ELF format. On the other hand, since these minimalist binaries
typically contain such little code, using fully-featured debuggers and such would actually be overkill; one may have a good laugh about how NSA's Ghidra cannot 
properly load their tiny ELF file, but attempting to do this is akin to trying to shoot down a fruitfly with a railgun - heavyweight frameworks packaged with debuggers and/or 
decompilers are unsuitable and unecessary for analyzing the runtime behavior of executables literally 45 or 62 bytes in size. If there are 10 bytes of code in a program,
does it make sense to try to load it into a decompiler? Probably not. A simple script emulating the execution of these programs may be a more appropriate approach.

# tiny-i386: 45 bytes total, 7 bytes of code

This is the "Tiny" program from [A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux](http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html).
This program, as well as the rest of the "Teensy" ELF files can be downloaded from the [muppetlabs site](http://www.muppetlabs.com/~breadbox/software/tiny/).

The approach taken here to analyzing this file is as follows:
 - attempting analysis with `readelf`, `gdb` and `r2`
 - looking at the source code
 - emulation

### Using Standard Tools to Parse the file

It should be noted at the outset that the binary can be loaded and executed without any problems:

```shell
$ strace ./tiny-i386 
execve("./tiny-i386", ["./tiny-i386"], 0x7ffc2a421f60 /* 52 vars */) = 0
strace: [ Process PID=30049 runs in 32 bit mode. ]
exit(42)                                = ?
+++ exited with 42 +++
```

However when `readelf` is used to try to read the program's ELF header, it fails:
```shell
$ readelf -h tiny-i386 
readelf: Error: tiny-i386: Failed to read file header
```

`gdb` fails to recognize that it is indeed an ELF file:
```shell
$ gdb -q tiny-i386
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
"home/reversing/tiny-i386": not in executable format: File format not recognized
gef➤  info file
gef➤  run
Starting program:  
No executable file specified.
Use the "file" or "exec-file" command.
gef➤  
```

In a pleasant surprise, we are able to debug and disassemble the code using r2:
```shell
$ r2 -d tiny-i386 
Process with PID 29855 started...
= attach 29855 29855
bin.baddr 0x00010000
Using 0x10000
Warning: Cannot initialize program headers
Warning: Cannot initialize section headers
Warning: Cannot initialize strings table
Warning: Cannot initialize dynamic strings
Warning: Cannot initialize dynamic section
Warning: read (init_offset)
asm.bits 32
[0x00010020]> ds
[0x00010020]> ds
[0x00010020]> ds
[0x00010020]> ds
child exited with status 42

==> Process finished

Stepping failed!
Step failed
[0x00010020]> pd 10
            0x00010020      b32a           mov bl, 0x2a                ; ebx
            0x00010022      31c0           xor eax, eax
            0x00010024      40             inc eax
            ;-- eip:
            0x00010025      cd80           int 0x80                     <---------- execution ends here
            0x00010027      003400         add byte [eax + eax], dh
            0x0001002a      2000           and byte [eax], al
            0x0001002c  ~   0100           add dword [eax], eax
            ;-- section_end.ehdr:
            0x0001002d      0000           add byte [eax], al
            0x0001002f      0000           add byte [eax], al
            0x00010031      0000           add byte [eax], al
[0x00010020]> 
```

However, when radare2 is used to parse the binary, some of the field values look really crazy:
```shell
$ r2 -nn tiny-i386 
[0x00000000]> pf.elf_header @ elf_header
     ident : 0x00000000 = .ELF.
      type : 0x00000010 = type (enum elf_type) = 0x2 ; ET_EXEC
   machine : 0x00000012 = machine (enum elf_machine) = 0x3 ; EM_386
   version : 0x00000014 = 0x00010020
     entry : 0x00000018 = 0x00010020
     phoff : 0x0000001c = 0x00000004
     shoff : 0x00000020 = 0xc0312ab3
     flags : 0x00000024 = 0x0080cd40
    ehsize : 0x00000028 = 0x0034
 phentsize : 0x0000002a = 0x0020
     phnum : 0x0000002c = 0xff01
 shentsize : 0x0000002e = 0xffff
     shnum : 0x00000030 = 0xffff
  shstrndx : 0x00000032 = 0xffff
[0x00000000]> 
```

There do seem to be quite a few odd-looking values mixed together with ones that align with what we are accustomed to seeing. What is happening here?

### A Look at the Source Code

Here is the source code:
```asm
  ; tiny.asm
  
  BITS 32
  
                org     0x00010000
  
                db      0x7F, "ELF"             ; e_ident
                dd      1                                       ; p_type
                dd      0                                       ; p_offset
                dd      $$                                      ; p_vaddr 
                dw      2                       ; e_type        ; p_paddr
                dw      3                       ; e_machine
                dd      _start                  ; e_version     ; p_filesz
                dd      _start                  ; e_entry       ; p_memsz
                dd      4                       ; e_phoff       ; p_flags
  _start:
                mov     bl, 42                  ; e_shoff       ; p_align
                xor     eax, eax
                inc     eax                     ; e_flags
                int     0x80
                db      0
                dw      0x34                    ; e_ehsize
                dw      0x20                    ; e_phentsize
                db      1                       ; e_phnum
                                                ; e_shentsize
                                                ; e_shnum
                                                ; e_shstrndx
  
  filesize      equ     $ - $$
```

A few observations:
 - the program header overlaps with the ELF header
 - the entry point is inside the ELF header 
    - The implication is that there is executable code inside the header
 - the fields having to do with sections are empty
    - it is actually more precise to say that since the file is 45 bytes in size but the ELF header of a 32-bit
      binary should be 52 bytes, those fields are simply not there.

As it turns out, the subset of fields that must contain correct values is as follows:
 - The first 4 bytes of *e_ident* which includes:
    - EI_MAG0 - EI_MAG4: `0x7f`, `E`, `L`, `F`
 - *e_type*
 - *e_machine*
 - *e_entry*
 - *e_phoff*
 - *e_phnum*

Summary from "A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux" (bolding added):
 > So: Here's what is and isn't essential in the ELF header. The **first four bytes** have to contain the magic number, or else Linux won't touch it. 
   The other three bytes in the e_ident field are not checked, however, which means we have no less than twelve contiguous bytes we can set to anything at all. 
   **e_type** has to be set to 2, to indicate an executable, and **e_machine** has to be 3, as just noted. e_version is, like the version number inside e_ident, 
   completely ignored. (Which is sort of understandable, seeing as currently there's only one version of the ELF standard.) **e_entry** naturally has to be valid, 
   since it points to the start of the program. And clearly, **e_phoff** needs to contain the correct offset of the program header table in the file, 
   and **e_phnum** needs to contain the right number of entries in said table. e_flags, however, is documented as being currently unused for Intel, 
   so it should be free for us to reuse. e_ehsize is supposed to be used to verify that the ELF header has the expected size, but Linux pays it no mind. 
   e_phentsize is likewise for validating the size of the program header table entries. This one was unchecked in older kernels, but now it needs to be set 
   correctly. Everything else in the ELF header is about the section header table, which doesn't come into play with executable files.

As stated previously, aside from the fields read by the kernel to load the program, the rest may contain arbitrary values. Naturally, if parsers rely on
the presence of appropriate values in fields not essential to loading in order to function properly, they will fail to read non-standard headers correctly.

### Emulation

Given that the program contains only 7 bytes of instructions and has a malformed header, emulation is a good alternative to heavyweight tools like radare2, IDA, 
Ghidra, etc. for analyzing/tracing/logging the runtime behavior of this kind of program. The program's code can be emulated via a small python script that utlizes
the [Unicorn Engine](http://www.unicorn-engine.org/) (at time of writing, the [Qiling emulation framework](https://github.com/qilingframework/qiling) is still in
alpha and the code is not available). That the header is malformed is irrelevant from the perspective of emulation, as the only information needed to emulate
the binary is its architecture and the file offsets at which to begin and end emulation; this information can be retrieved from a hex dump of the binary 
without needing to parse the ELF header.

The approach to emulating the `tiny-i386` binary is as follows:

First, retrieve the start and end points for emulation from a hex dump. Then, when writing the script to emulate the program:
 - read the file and map it to memory
 - set up the stack
 - initialize the emulation engine
 - implement a hook that allows each executed instruction to be traced and logged to STDOUT
   - a Capstone disassembly engine object will be passed to this hook so that each instruction can be disassembled and its disassembly logged as well
 - implement a hook that handles system calls

We know from the source code that the first instruction is `mov bl, 42` and the final instruction is `int 0x80`. We can find these easily in a dump of `tiny-i386`:

```shell
$ hexdump -C tiny-i386 
00000000  7f 45 4c 46 01 00 00 00  00 00 00 00 00 00 01 00  |.ELF............|
00000010  02 00 03 00 20 00 01 00  20 00 01 00 04 00 00 00  |.... ... .......|
00000020  b3 2a 31 c0 40 cd 80 00  34 00 20 00 01           |.*1.@...4. ..|
0000002d
```

Narrowing down the output:
```shell
$ hexdump -C -s 0x20 -n 7 tiny-i386 
00000020  b3 2a 31 c0 40 cd 80                              |.*1.@..|
00000027
```

There we have it: the offset at which to begin emulation is `0x20` and at which to end is `0x27`.

Since the architecture is already known to us, this is all the information required to emulate the program:

<script src="https://gist.github.com/BinaryResearch/a4f9bf18ca06236baa5956f3b55878f4.js"></script>

When executed, we get a trace + disassembly:
```shell
$ ./emulate_tiny-i386.py 
>>> Tracing instruction at 0x100020, instruction size = 0x2, disassembly:	mov	bl, 0x2a
>>> Tracing instruction at 0x100022, instruction size = 0x2, disassembly:	xor	eax, eax
>>> Tracing instruction at 0x100024, instruction size = 0x1, disassembly:	inc	eax
>>> Tracing instruction at 0x100025, instruction size = 0x2, disassembly:	int	0x80
>>> 0x100025: INTERRUPT: 0x80, EAX = 0x1
>>> Emulation Complete.
```

Nice. No debugger needed.

# bye: 84 bytes total, 23 bytes of code

An advantage of emulation over debugging is that the emulated instructions have no effect on the host system. Even if the program being emulated
contains code that could potentially damage the system it runs on, it is not being executed, so there is no danger (unless there is some way to 
escape from the emulator, e.g. [QEMU VM escape](http://www.phrack.org/papers/vm-escape-qemu-case-study.html)). This is useful for analyzing viruses,
crimeware, etc. and in this case @Netspooky's `bye` binary which executes the `reboot` syscall with the `LINUX_REBOOT_CMD_POWER_OFF` argument:

> On a desktop system, this binary will shut down your computer abruptly. There are some potential side effects from a shutdown like this, 
  but personally I haven’t experienced any issues with it. However, on a VPS, this specific syscall proves to be a bit of a problem. Since the 
  virtual machine doesn’t actually have any of it’s own physical hardware (it’s either virtualized or shared with the host), the power button 
  on a VPS isn’t really a thing. By executing a syscall the effectively “shuts off the power” to the operating system, this puts the VM in an unknown state.
  So far, whenever this is run on a VPS, it seemingly wipes out the entire instance.

It is clearly advantageous to be able analyze the runtime behavior of such a program without having to actually load it into memory and execute.
The script used to analyze `tiny-i386` can be modified to support emulation of x86-64 code and of the `reboot` syscall. The same approach will be followed
as before, with minor adjustments.

Before we begin, however, we can first try to read the file's ELF header with `readelf` and then disassemble its code with Capstone to get a sense of
what to expect from emulation.

### Parsing the Header with readelf

```shell
$ readelf -h bye
ELF Header:
  Magic:   7f 45 4c 46 ba dc fe 21 43 be 69 19 12 28 eb 3c 
  Class:                             <unknown: ba>
  Data:                              <unknown: dc>
  Version:                           254 <unknown: %lx>
  OS/ABI:                            <unknown: 21>
  ABI Version:                       67
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4
  Start of program headers:          1 (bytes into file)
  Start of section headers:          28 (bytes into file)
  Flags:                             0x0
  Size of this header:               0 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           0 (bytes)
  Number of section headers:         1
  Section header string table index: 0
readelf: Warning: possibly corrupt ELF header - it has a non-zero program header offset, but no program headers
``` 

The ELF header is clearly malformed. At least we can see the entry point is at offset `0x4`. 

### Disassembly with Capstone and Radare2

According to the comments in the [source
code of the file](https://gist.github.com/netspooky/dd750e7ced85fb1861780a90be71053d#file-bye-asm), 
the last instruction is located at the last byte of the file - offset `0x53`. Using this information, a simple script to disassemble the code
with Capstone can be written:

<script src="https://gist.github.com/BinaryResearch/c751ae183aafda9f3dd2167326e2bd3f.js"></script>

This produces the following disassembly:

```shell
$ ./disassemble_bye.py 
0x1000:	mov	edx, 0x4321fedc
0x1005:	mov	esi, 0x28121969
0x100a:	jmp	0x1048
0x100c:	add	al, byte ptr [rax]
0x100e:	add	byte ptr ds:[rcx], al
0x1011:	add	byte ptr [rax], al
0x1013:	add	byte ptr [rax + rax], al
0x1016:	add	byte ptr [rax], al
0x1018:	add	dword ptr [rax], eax
0x101a:	add	byte ptr [rax], al
0x101c:	sbb	al, 0
0x101e:	add	byte ptr [rax], al
0x1020:	add	byte ptr [rax], al
0x1022:	add	byte ptr [rax], al
0x1024:	add	byte ptr [rax], al
0x1026:	add	byte ptr [rax], al
0x1028:	add	byte ptr [rax], al
0x102a:	add	byte ptr [rax], al
0x102c:	add	dword ptr [rax], eax
0x102e:	add	byte ptr [rax], al
0x1030:	add	byte ptr [rax], dil
0x1033:	add	byte ptr [rcx], al
0x1035:	add	byte ptr [rdx], al
0x1037:	add	byte ptr [rax + 0x50fa9], dh
0x103d:	add	byte ptr [rax], al
0x103f:	add	byte ptr [rax + 0x50fa9], dh
0x1045:	add	byte ptr [rax], al
0x1047:	add	byte ptr [rdi - 0x11e2153], bh
0x104d:	jmp	0x1038
0x104f:	nop	
```

This is clearly incorrect. Based on this disassembly, there are no syscalls being made, when we know for a fact that they are in the source. What happened?
As it turns out, Capstone is a *linear sweep*-based disassembler (as opposed to *recursive traversal*-based, like radare2)[1][2]. This means that beginning at
the start address, it disassembles all bytes as code until the end address, ignoring flow-of-control. In the disassembly above, quite a bit of null bytes and
data are being decoded as instructions. We can compensate for this manually somewhat by ignoring the bytes between the `jmp` at offset `0xa` and the `cya` label
at offset `0x3c` (see the source code):

<script src="https://gist.github.com/BinaryResearch/7ba21aa05deddf507fa8a6fb7edf41c3.js"></script>

The disassembly produced after these adjustments is less egregiously erroneous (but still not quite correct):
```shell
$ ./disassemble_bye_2.py 
0x1000:	mov	edx, 0x4321fedc
0x1005:	mov	esi, 0x28121969
0x100a:	jmp	0x1048                <------- jumps beyond the end of the buffer
0x100c:	mov	al, 0xa9
0x100e:	syscall	
0x1010:	add	byte ptr [rax], al    <------- error
0x1012:	add	byte ptr [rax], al    <------- error
0x1014:	mov	al, 0xa9
0x1016:	syscall	
0x1018:	add	byte ptr [rax], al    <------- error
0x101a:	add	byte ptr [rax], al    <------- error
0x101c:	mov	edi, 0xfee1dead
0x1021:	jmp	0x100c
0x1023:	nop	

```
At least it somewhat resembles the source code.

How does radare2 fare in disassembling this binary? Not well at all. In fact, it completely fails (maybe I am not using the correct flags?):
```shell
$ r2 bye
Warning: Cannot initialize program headers
Warning: Cannot initialize dynamic strings
Warning: Cannot initialize dynamic section
[0x00000004]> pd
            ;-- entry0:
            ;-- eip:
            0x00000004      ff             invalid
            0x00000005      ff             invalid
            0x00000006      ff             invalid
            0x00000007      ff             invalid
            0x00000008      ff             invalid
            0x00000009      ff             invalid
            0x0000000a      ff             invalid
            0x0000000b      ff             invalid
            0x0000000c      ff             invalid
            0x0000000d      ff             invalid
            0x0000000e      ff             invalid
            0x0000000f      ff             invalid
            0x00000010      ff             invalid
            0x00000011      ff             invalid
            0x00000012      ff             invalid
            0x00000013      ff             invalid
            0x00000014      ff             invalid
            0x00000015      ff             invalid
            0x00000016      ff             invalid
            0x00000017      ff             invalid
            0x00000018      ff             invalid
            0x00000019      ff             invalid
            0x0000001a      ff             invalid
            0x0000001b      ff             invalid
            0x0000001c      ff             invalid
            0x0000001d      ff             invalid
            0x0000001e      ff             invalid
            0x0000001f      ff             invalid
            0x00000020      ff             invalid
            0x00000021      ff             invalid
            0x00000022      ff             invalid
            0x00000023      ff             invalid
            0x00000024      ff             invalid
            0x00000025      ff             invalid
            0x00000026      ff             invalid
            0x00000027      ff             invalid
            0x00000028      ff             invalid
            0x00000029      ff             invalid
            0x0000002a      ff             invalid
            0x0000002b      ff             invalid
            0x0000002c      ff             invalid
            0x0000002d      ff             invalid
            0x0000002e      ff             invalid
            0x0000002f      ff             invalid
            0x00000030      ff             invalid
            0x00000031      ff             invalid
            0x00000032      ff             invalid
            0x00000033      ff             invalid
            ;-- section_end.ehdr:
            0x00000034      ff             invalid
            0x00000035      ff             invalid
            0x00000036      ff             invalid
            0x00000037      ff             invalid
            0x00000038      ff             invalid
            0x00000039      ff             invalid
            0x0000003a      ff             invalid
            0x0000003b      ff             invalid
            0x0000003c      ff             invalid
            0x0000003d      ff             invalid
            0x0000003e      ff             invalid
            0x0000003f      ff             invalid
            0x00000040      ff             invalid
            0x00000041      ff             invalid
            0x00000042      ff             invalid
            0x00000043      ff             invalid
[0x00000004]> 
```

Looks like disassembly is not particularly helpful here. 

# Emulation

Emulation seems to be our only reasonable option. The program responsible for handling emulation of `bye` includes code
that is triggered when the `reboot` syscall is made, allowing us to see the arguments in the registers:

<script src="https://gist.github.com/BinaryResearch/539ba8a73d79eb211503c7e87ae43242.js"></script>

Emulation execution trace:
```shell
$ ./emulate_bye.py 
>>> Tracing instruction at 0x100004, instruction size = 0x5, disassembly:	mov	edx, 0x4321fedc
>>> Tracing instruction at 0x100009, instruction size = 0x5, disassembly:	mov	esi, 0x28121969
>>> Tracing instruction at 0x10000e, instruction size = 0x2, disassembly:	jmp	0x10004c
>>> Tracing instruction at 0x10004c, instruction size = 0x5, disassembly:	mov	edi, 0xfee1dead
>>> Tracing instruction at 0x100051, instruction size = 0x2, disassembly:	jmp	0x10003c
>>> Tracing instruction at 0x10003c, instruction size = 0x2, disassembly:	mov	al, 0xa9
>>> Tracing instruction at 0x10003e, instruction size = 0x2, disassembly:	syscall	
>>> got SYSCALL with RAX = 169
>>> SYSCALL:	reboot
>>> ARGUMENTS:	RDI = 0xfee1dead	RSI = 0x28121969	RDX = 0x4321fedc
>>> Emulation Complete.
```

Very nice. Not only do we see the runtime behavior of the program without executing it, but we get essentially correct disassembly as well. 
According to the source code and the attempt at disassembly using Capstone, the `reboot` syscall is made twice, but obviously only the first one would
ever be executed, meaning the instructions following the first `reboot` syscall are unreachable. Perhaps emulation is also good for analysing obfuscated
assembly code? (hint, hint)

# Conclusion

As we can see, emulation is very useful for analyzing programs that can't be properly parsed or disassembled with the ususal tools. However, the difficulty
of writing the program that performs the emulation via Unicorn scales with the complexity of the program being emulated. An example of this is the necessity
of implementing support for interrupts and syscalls. In the next post, programs with malformed headers that also make calls to shared library functions will
be emulated as well. Furthermore, up to this point the start and end addresses of emulation have been manually retrieved; a method of parsing malformed ELF
headers will also be explored so that the code start and end offsets can be retrieved in an automated fashion.

# Links and References

1. [Disassembly of Executable Code Revisited](https://www2.cs.arizona.edu/~debray/Publications/disasm.pdf) - discusses linear sweep and recursive traversal disassembly algorithms
2. [On Disassembling Obfuscated Assembly](https://silviocesare.wordpress.com/2007/11/17/on-disassembling-obfuscated-assembly/)

Muppetlabs' Tiny Binaries:
 - [The Teensy Files](http://www.muppetlabs.com/~breadbox/software/tiny/)

netspooky's Experiments:
 - [source code of "golfclub" binaries on github](https://github.com/netspooky/golfclub)
 - [ELF Binary Mangling Part 1 — Concepts](https://medium.com/@dmxinajeansuit/elf-binary-mangling-part-1-concepts-e00cb1352301)
 - [Elf Binary Mangling Pt. 2: Golfin’](https://medium.com/@dmxinajeansuit/elf-binary-mangling-pt-2-golfin-7e5c82bb482c)
 - [Elf Binary Mangling Part 3 — Weaponization](https://medium.com/@dmxinajeansuit/elf-binary-mangling-part-3-weaponization-6e11971108b3)

Unicorn Engine materials:
 - [Unicorn Engine tutorial](http://eternal.red/2018/unicorn-engine-tutorial/)
 - [Unicorn Engine Reference (Unofficial)](https://hackmd.io/@K-atc/rJTUtGwuW?)
 - [sample_x86.py](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_x86.py)
 - [shellcode.py](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/shellcode.py)
