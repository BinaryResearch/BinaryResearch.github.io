---
layout: post
title: More angr - Defeating 5 ELF Crackmes
tags: [angr, cutter, qiling, emulation, symbolic-execution, crackme, reverse-engineering, ELF, Linux]
author-id: julian
---

The purpose of this post is to demonstrate how emulation can be used to find solutions to a few keygenme-style crackme programs. 
It is not always necessary or efficient to rely on just a disassembler or debugger when emulation can be used to assist with the analysis.
In fact, by using tools like angr and Cutter one can save a significant amount of time when solving challenges like these.
Rather than post each write-up seperately, the solutions to 5 challenges are posted together here. 
They are of rather low difficulty, so they should be accessible to beginners.


### Contents:

 1. Bkamp's `glow wine` - keygenme
 2. Exxtra12's `xordemo` - password
 3. kawaii-flesh's `key and keygen` - 1 password per username
 4. m3hd1's `half-twins` - keygenme
 5. paypain's `de_tcrack1` - keygenme

### Arsenal

 - [angr](https://angr.io/)
 - [Qiling](https://github.com/qilingframework/qiling) (used to solve #3)
 - [Cutter](https://cutter.re)

<hr>

# 1) Bkamp's glow wine 
## a Webkinz-level keygenme

- Emulator: angr
- Solve time: ~1 second.

 - [Challenge page](https://crackmes.one/crackme/5df26b4033c5d419aa013362)
 - [Challenge download](https://crackmes.one/static/crackme/5df26b4033c5d419aa013362.zip)
 - Password to unzip: crackmes.one

The decompilation (courtesy of the Ghidra decompiler integrated with Cutter) illustrates the constraints a solution must conform to:

```java
undefined8 main(undefined8 argc, char **argv)
{
    int64_t iVar1;
    char **s;
    undefined8 var_4h;
    
    if ((int32_t)argc < 2) {
        sym.imp.puts(0x848);
    } else {
        iVar1 = sym.imp.strlen(argv[1]);
        if (iVar1 != 5) {
            sym.sorrybro();
        }
        if (argv[1][1] != '@') {
            sym.sorrybro();
        }
        if ((int32_t)argv[1][4] + (int32_t)argv[1][2] + (int32_t)argv[1][3] != 300) {
            sym.sorrybro();
        }
        sym.imp.puts(0x860);
    }
    return 0;
}
```

Demo:

<script id="asciicast-kv1tpqeYmVKG3LTvhc5xAdAp2" src="https://asciinema.org/a/kv1tpqeYmVKG3LTvhc5xAdAp2.js" async data-rows="35" data-cols="150" data-speed="2"></script>

Here is a script using angr to compute keys:
<script src="https://gist.github.com/BinaryResearch/5576f56e5673f7f9e860cf1c5729b764.js"></script>



# 2) Exxtra12's xordemo 
## single solution, input XORed

 - Emulator: angr
 - Solve time:  Less than 1 second.

 - [Challenge page](https://crackmes.one/crackme/5dfd77a833c5d419aa013406)
 - [Crackme download](https://crackmes.one/static/crackme/5dfd77a833c5d419aa013406.zip)
 - Password to unzip: crackmes.one

The input is XORed with some hardcoded data to determine if it is correct. The correct input results in `Jackpot` being output to stdout.
This program is very simple - there are only 2 functions that concern us and very few branches in flow-of-control. In addition, the symbol
table has not been removed from the binary.

### main

 - if `argc` == 2, `argv[1]` is passed as an argument to `checkPassword`
 - after `checkPassword` returns, if the value is 0, print "fail". Else, print "Jackpot".

<img src="{{site.baseurl}}/assets/img/2020-1-22-shooting-gallery/xordemo_graph_main.png">

### checkPassword

 - loop over bytes in input string, XORing them with bytes in hardcoded string `badbeef1` 
 - upon success, return 1, else return 0

<img src="{{site.baseurl}}/assets/img/2020-1-22-shooting-gallery/xordemo_graph_sym_checkPassword.png">

### Demo

<script id="asciicast-NU5fbnG4c6ZtaiLVobUdxHwgz" src="https://asciinema.org/a/NU5fbnG4c6ZtaiLVobUdxHwgz.js" async data-rows="25" data-cols="150" data-speed="2"></script>

### Script

<script src="https://gist.github.com/BinaryResearch/0aa4c544ac5a45989e86e9daac9dc3ef.js"></script>

# 3) Kawaii-flesh's key and keygen
##  input correct username-password pairs via stdin

 - Emulator: Qiling
 - Solve time: N/A
 - [Challenge page](https://crackmes.one/crackme/5d17962b33c5d41c6d56e1f2)
 - [Crackme download](https://crackmes.one/static/crackme/5d17962b33c5d41c6d56e1f2.zip)
 - password to unzip: crackmes.one

The task of writing a program to generate solutions to this crackme was interesting due to the design of the program. The crackme
takes a username and password as inputs from `stdin` and then computes a password based on the byte values in the username. This computed password
is then checked against the password input from stdin; if they match, the challenge is solved.

In sum:
 - for every username, there is only 1 correct password
 - the correct password is calculated by the crackme at runtime

All one has to do to find a single solution is set a breakpoint after the password is calculated and inspect the buffer it is written to.
The real goal is to automate this.

### main

After `scanf` reads the username and password from stdin, a buffer of length 10 is allocated on the heap; a pointer to this buffer is passed to the
`encr` function along with a pointer to the buffer holding the username.

When `encr` returns after calculating the password, the buffer on the heap holds this password. That password is then compared with the one that was read by `scanf`.

<img src="{{site.baseurl}}/assets/img/2020-1-22-shooting-gallery/graph_kawaii_keygen1_main.png">

### encr

It is actually not necessay to analyze the `encr` function to understand how the password is calculated if the password can be retrieved automatically.
It has a single exit point, which is returning to `main`.

<img src="{{site.baseurl}}/assets/img/2020-1-22-shooting-gallery/graph_kawaii_keygen1_encr.png">

There are several approaches to accomplishing the task of automatically generating a list of acceptable username-password pairs. 
The most traditional would be to reverse engineer and study the algorithm responsible for creating the key and then writing a program in a higher-level language
that implements this algorithm. In light of the fact that the program computes the password for us already, this sounds quite a bit of unnecessary work; 
something that can be done
instead is to execute the crackme for each new username and then retrieve the password for that username from memory. For example, since the crackme is a 
dynamically-linked binary 
and the `strcmp` function is used to compare the password from stdin to the one computed by the crackme, one option for retrieving the password is hooking
`strcmp` and injecting code from a custom shared library using LD_PRELOAD. The injected code can simply output the arguments passed to `strcmp`.

The approach chosen here however is emulating the crackme binary with Qiling and hooking an address at which the password has already been calculated and
the memory address of the password buffer is in a register, making its retrieval straightforward. This can be done for each new username that that we want
to input to the crackme.

### Demo:

<script id="asciicast-YuAqisKMjEyflfkF4E1XxhEyj" src="https://asciinema.org/a/YuAqisKMjEyflfkF4E1XxhEyj.js" async data-rows="30" data-cols="200" data-speed="2"></script>

The solution demonstrated above involves 2 programs:

 - `emulate_keygenme.py` emulates the crackme such that for a given username, the password calculated in `encr` is printed to stdout:

<script id="asciicast-aTMEaiIgWC1F4JygGw85fcM0c" src="https://asciinema.org/a/aTMEaiIgWC1F4JygGw85fcM0c.js" async data-rows="27" data-cols="170" data-speed="2"></script>

As we can see, input entered at the "key" prompt has no bearing on the actual key/password. Only the username string matters.

Here is the code for `emulate_keygenme.py`

<script src="https://gist.github.com/BinaryResearch/b1b2df950a168525253e01ae589c80e9.js"></script>

 - `kawaii_keygen.py` below performs the following:
  1. generates a list of usernames
  2. for each username in the list, executes `emulate_keygenme.py`
        - the output of the emulation contains the password generated for that username
  3. executes the crackme, inputting the username and the password to confirm that they are correct
  4. prints the output

<script src="https://gist.github.com/BinaryResearch/e31296ab6112f21ed5bffbed74aa59db.js"></script>

# 4) m3hd1's half-twins
## input 2 valid command-line arguments

 - Emulator: angr
 - Solve time: ~3 seconds per solution
 - [Challenge page](https://crackmes.one/crackme/5dce805c33c5d419aa0131ae)
 - [Crackme download](https://crackmes.one/static/crackme/5dce805c33c5d419aa0131ae.zip)
 - password to unzip: crackmes.one

The order of characters in the arguments to the program plus the relationship between the arguments together is what really matters in this case,
so it is essential here to limit the range of possible byte values in solutions to printable ASCII characters in order for the program to accept 
them as valid. Here are some example solutions:

 - `hbbbpfpb`, `hbbbxbrp`
 - `BHAPPHAP`, `BHAPBBHB`

As long as the first 4 (out of 8) characters of the 2 strings match, the strings are accepted as solutions. This means the set of solutions
is extremely large.

### main

The entirety of the crackme code is in the `main` function. The code printing the message indicating success is at `0x0000134e`. The program
expects 2 arguments of length 8:

<img src="{{site.baseurl}}/assets/img/2020-1-22-shooting-gallery/half-twins_graph_main.png">

### Demo

<script id="asciicast-3TRyICGXzbazxuaZ130Gz3OH5" src="https://asciinema.org/a/3TRyICGXzbazxuaZ130Gz3OH5.js" async data-rows="30" data-speed="10"></script>

### Script

<script src="https://gist.github.com/BinaryResearch/4aacd891019354ed552c5d2de5df0955.js"></script>

# 5) paypain's de_tcrack1
## input valid arg longer than 10 chars

 - Emulator: angr
 - Solve time: ~3 seconds total
 - [Challenge page](https://crackmes.one/crackme/5c9d9eea33c5d4419da55641)
 - [Crackme download](https://crackmes.one/static/crackme/5c9d9eea33c5d4419da55641.zip)
 - password to unzip: crackmes.one

To solve this crackme, 2 requirements must be met:
  - the input string must pass all the checks in basic blocks
0x00001080, 0x0000109c, 0x000010b0, and 0x000010c6
  - the string must be the correct length. This information is contained in the
    logic of the larger basic block at 0x00001107

### main

`angr` can be used to efficiently compute strings that pass the various checks
preceding basic block 0x00001107. If the correct length is specified, setting the target address for exploration to 0x00001107 
is sufficient to compute valid keys. I was not able to successfully use angr to emulate the code at 0x0000111b and beyond, but solutions can
be generated without exploring that far.

<img src="{{site.baseurl}}/assets/img/2020-1-22-shooting-gallery/paypain-de_tcrack1-graph_main.png">

It turns out that the computations in basic block 0x00001107 append the input
string together with `FL4GiNyOUrMinD` and `WiNAll`,  2 strings hardcoded in the `.rodata` section.
For example, if the input string is `bb??@???b?A?`, then in memory this composite string looks like this: `FL4GiNyOUrMinDbb??@???b?A?WiNAll`. 

<img src="{{site.baseurl}}/assets/img/2020-1-22-shooting-gallery/paypain-de_tcrack1-bb_0x00001107-highlighted.png">

When the input string is 10 characters long, the value in RDX at 0x00001162 is `0x1e`. If the input string is longer than this,
the crackme is solved and the license is printed to stdout.

### Demo  

<script id="asciicast-fPhgezaXGM5M8Abm5tiQIJcgd" src="https://asciinema.org/a/fPhgezaXGM5M8Abm5tiQIJcgd.js" async data-rows="30" data-cols="170"></script>

When typed in the terminal, the output looks like this:

```
$ ./de_tcrack1 "????@??bbb+?"

[+] Login Complete
[+] License->FL4GiNyOUrMinD????@??bbb+?WiNAll
```

The "Login Complete" line is excluded from the script output.

### Script

<script src="https://gist.github.com/BinaryResearch/4c071d95d3867033382df080c6496f3b.js"></script>
