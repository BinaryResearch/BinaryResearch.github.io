---
layout: post
title: Inserting Debugging Instrumentation into an Internal Function Using Redirect-to-PLT
tags: [hooking, reverse-engineering, instrumentation, debugging, ELF, LD_PRELOAD, redirect-to-PLT, AMD64, x86-64, PIE]
author-id: julian
---

In the previous post, it was demonstrated how an internal function in a dynamically-linked 
ELF executable can be hooked by redirecting execution to the PLT entry of a shared library function and 
then overriding that shared library function via `LD_PRELOAD`. This technique 
was used to completely replace the logic of an internal function of a toy program. 
This time, rather than substituting the logic of a hooked internal function in its entirety
in order to override the function's behavior, it will be demonstrated how debugging instrumentation can be
inserted into a hooked internal function to analyze and log its runtime behavior.
The internal function responsible for encoding a key via XOR operations in a crackme program
will be analyzed. 

### Overview
 
The following will be discussed:

 - the requirements for using this technique to monitor internal function behavior
 - how to re-implement the logic of an internal function in a custom shared library

Prerequisites:

 - familiarity with the concepts introduced in the previous post
 - knowing how to use a decompiler
 - x86-64 stack frame layout and calling convention
 - a basic understanding of GCC's extended ASM and x86-64 assembly

Tools:

 - Ghidra
 - GCC


# Introduction

When using the redirect-to-PLT method to hook an internal function at a particular juncture, 
a shared library function is called instead of that internal function. It is important to emphasise this 
implies that in order to analyze and study runtime behavior of the hooked 
internal function using this method, its logic needs to be recreated in the custom shared 
library injected as the hook. 

For the analysis to be meaningful,
the following conditions will ideally be met:

 - for the same set of inputs (arguments) as the internal function, the hook must produce the same set of outputs (return values)
 - the code of the injected hook should be semantically equivalent to the code of the internal 
function, to the extent that the runtime behavior of the injected hook mirrors 
   that of the hooked internal function

If the logic of the injected code imitates that of the hooked internal 
function to a sufficient extent, insertion of debugging instrumentation into the code
of the injected hook will allow us to log the operations performed by the function 
at runtime while preserving the semantics of the program.

# Logging the Encoding of a Key in an Internal Function

The level 1 crackme program by kawaii-flesh called "Simple crackme"  will be used to demonstrate how the redirect-to-PLT trick can be used
to insert debugging instrumentation into the logic of an internal function. To solve this crackme, one needs to supply the correct
input string to the program from STDIN. The input is compared with a key that is encoded in an internal function, which will be hooked and monitored.

The approach is as follows:

 1. Hook the internal function responsible for encoding the key.
 2. The logic of the hooked internal function will be recreated in a custom shared library
 3. Code responsible for logging operations of interest will be inserted into the recreated logic
 4. That library will be injected at runtime. 
 5. At runtime, the injected code will log the function's operations to STDOUT, allowing us to retrieve the encoded key.

However, the program must be examined first. 

### Crackme Program Overview

The program can be downloaded
from its [crackmes.one page](https://crackmes.one/crackme/5d0d1e1333c5d41c6d56e155). The password to unzip it is "crackmes.one". 
This particular crackme can be solved manually in approximately 5 seconds by using `ltrace` to recover the
password, though many other methods could be used instead:

```shell
$ ltrace ./crackme 
printf("Enter key: ")                                                                                   = 11
__isoc99_scanf(0x55f7c4fe1010, 0x7ffdbb6115c0, 0, 0Enter key: 4
)                                                    = 1
strcmp("4", "bd4c217637bc828982c090b2de41b84d"...)                                                      = -46
puts("try again!"try again!
)                                                                                      = 11
+++ exited (status 0) +++
```

As indicated in the output, the key is `bd4c217637bc828982c090b2de41b84d`.

For the sake of this demonstration, we can ask 

 - Where does this key come from? 
 - How is it calculated? 

When the program is analyzed, it can be seen that 

 1. a string declared in `main()` is passed to a function that
encodes it 
 2. the function returns the encoded string. 
 3. Input from the user is then compared with that encoded string

```c
// in main()

undefined8 FUN_001011c6(void)

{
  long lVar1;
  int iVar2;
  char *password;
  long in_FS_OFFSET;
  undefined8 local_1a8;
  undefined8 local_1a0;
  undefined8 local_198;
  undefined8 local_190;
  undefined local_188;
  undefined8 local_178;
  undefined8 local_170;
  undefined8 local_168;
  undefined8 local_160;
  undefined local_158;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined8 local_130;
  undefined local_128;
  char input [264];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);		<------------------- stack guard variable
  local_1a8 = 0x3534323160376761;                       <------------------- string to encode
  local_1a0 = 0x3a3b313b60613430;
  local_198 = 0x3161333a3360313b;
  local_190 = 0x67373b6132376667;
  local_188 = 0;
  local_178 = 0x3533356431383331;
  local_170 = 0x3638323930383737;
  local_168 = 0x3065633735393638;
  local_160 = 0x6161653163396262;
  local_158 = 0;
  local_148 = 0x61313b323a3b373b;
  local_140 = 0x6166676060313b3a;
  local_138 = 0x6031316135326133;
  local_130 = 0x6734673730333734;
  local_128 = 0;
  printf("Enter key: ");
  __isoc99_scanf("%s",local_118);			 <-------------------- read user input
  __s2 = (char *)FUN_00101179(&local_1a8,0x20,3);        <-------------------- encode the string
  iVar2 = strcmp(local_118,__s2);                        <-------------------- compare encoded string with user input
  if (iVar2 == 0) {
    puts("good job!");
  }
  else {
    puts("try again!");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {	 <-------------------- check stack guard variable
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();	
  }
  return 0;
}

```

If the input matches the encoded key, the message "good job!" is printed.


Here is the code of the function responsible for encoding the key:

```c
/* called from main:  __s2 = (char *)FUN_00101179(&local_1a8,0x20,3);
                       local_1a8 = 0x3534323160376761 */

long FUN_00101179(long lParm1,int iParm2,byte bParm3)

{
  int local_c;
 
  local_c = 0;
  while (local_c < iParm2) {
    *(byte *)(lParm1 + (long)local_c) = *(byte *)(lParm1 + (long)local_c) ^ bParm3;
    local_c = local_c + 1;
  }
  return lParm1;
}
``` 

### Hooking the Encoding Function

To log how the key is encoded, we can hook this function with the redirect-to-PLT trick.
Here is an outline of the hooking procedure:

 1. Select a suitable shared library function to override
 2. Patch the CALL to the internal function to point to the PLT entry of the chosen shared library function
 3. Design the custom shared library to inject
 4. Use `LD_PRELOAD` to inject the shared library.

In this case, the shared library function chosen to be overridden is `__stack_chk_fail()`. This particular shared library function
is well suited for being overridden by a custom function via `LD_PRELOAD` for a few reasons:

 - It takes no arguments and does not return. This is an [simple function](https://code.woboq.org/userspace/glibc/debug/stack_chk_fail.c.html) 
   with a simple interface, making it straightforward to manipulate.
 - This function is called only to terminate the program if the guard variable in 
   the stack frame of a function (the so-called "stack-cookie") is overwritten.
   Since we are not writing buffer-overflow based exploits and no stack-smashing occurs at program runtime, this function will never be called.
   As a result, we can use `__stack_chk_fail()` for our purposes as we
   like, without having to worry about this function being called elsewhere in the program and encoding conditionals that determine 
   the exact circumstances the custom code for the internal function is triggered, simplifying the process of designing the shared library code
   to inject.

In the disassembly of `main()` we see that the encoding function is called at offset `0x1397`:

```shell
    138a:       ba 03 00 00 00          mov    $0x3,%edx               <------------- arg3
    138f:       be 20 00 00 00          mov    $0x20,%esi              <-------------   arg2
    1394:       48 89 c7                mov    %rax,%rdi	       <-------------     arg1
    1397:       e8 dd fd ff ff          callq  1179 <puts@plt+0x109>   <------------- call to encoding function
    139c:       48 89 c2                mov    %rax,%rdx
    139f:       48 8d 85 f0 fe ff ff    lea    -0x110(%rbp),%rax
    13a6:       48 89 d6                mov    %rdx,%rsi
    13a9:       48 89 c7                mov    %rax,%rdi
    13ac:       e8 af fc ff ff          callq  1060 <strcmp@plt>
```

In addition, the address of the PLT entry for `__stack_chk_fail()` is `0x1040`:

```shell
$ objdump -dj .text crackme | grep __stack
    13e8:	e8 53 fc ff ff       	callq  1040 <__stack_chk_fail@plt>
```

In a **copy of the crackme program**, we then patch the program such that instead of calling the internal function
that performs the encoding from `main()`, the shared library function`__stack_chk_fail()` is called instead:

<script src="https://gist.github.com/BinaryResearch/08d5e4502a334ffba1e41e4b15660f1b.js"></script>

After the address is patched, the change should be confirmed via disassembly:

```shell
    138a:       ba 03 00 00 00          mov    $0x3,%edx
    138f:       be 20 00 00 00          mov    $0x20,%esi
    1394:       48 89 c7                mov    %rax,%rdi
    1397:       e8 a4 fc ff ff          callq  1040 <__stack_chk_fail@plt>   <--------------------
    139c:       48 89 c2                mov    %rax,%rdx
    139f:       48 8d 85 f0 fe ff ff    lea    -0x110(%rbp),%rax
    13a6:       48 89 d6                mov    %rdx,%rsi
    13a9:       48 89 c7                mov    %rax,%rdi
    13ac:       e8 af fc ff ff          callq  1060 <strcmp@plt>
``` 

### Designing the Custom Library to Inject: Recreating the Logic of the Hooked Internal Function

Now that the internal function of interest has been hooked, we can focus on the design of the custom shared library to inject.
As mentioned previously, the logic of the encoding function that we want to insert code into must be recreated in the custom
library. Let us re-examine the decompiled code of the endoding function produced by Ghidra:

```c
long FUN_00101179(long lParm1,int iParm2,byte bParm3)

{
  int local_c;
 
  local_c = 0;
  while (local_c < iParm2) {
    *(byte *)(lParm1 + (long)local_c) = *(byte *)(lParm1 + (long)local_c) ^ bParm3;
    local_c = local_c + 1;
  }
  return lParm1;
}
```

It looks like the bytes of argument 1 to the function are iterated over and in each iteration the byte is XORed
by argument 3. The total number of bytes iterated over is equal to argument 2. The XORed version of argument 1 is
the return value.

We now know what is required to design the hook:

 1. Read 3 arguments from CPU registers RDI, RSI and RDX [1]
 2. Reproduce the algorithm of the hooked internal function encoding the string
 3. Place a pointer to the encoded string in RAX as the return value

The extended asm[2] functionality provided by GCC means we can read from and write to registers directly in C (what a time to be alive),
meaning that there is no need for writing any assembly in the program. Besides reading from and writing to the appropriate registers and
re-implementing the logic responsible for encoding the key, `printf()` statements will be added to the code so that we can see the input
string, how exactly the string is encoded to create the key, and what the final key is:

<script src="https://gist.github.com/BinaryResearch/f8cdaa7f1bca1136e53a34d28f7a12cc.js"></script>

compile:
```shell
$ gcc -shared -fPIC -o instrument_encoding_function.so instrument_encoding_function.c
```
inject:
```shell
$ LD_PRELOAD=$PWD/instrument_encoding_function.so ./copy_of_crackme
```

The output produced lets us see very clearly the input to the function, its internal operations, and its output:

```shell
Enter key: 4							<-------- user input
RDX: 7ffe3e5ad330	RSI: 0x20	RDX: 0x3		<-------- function arguments
key address = 0x7ffe3e5ad330	i = 0x20	j = 0x3		<-------- args saved in local variables
key: ag7`124504a`;1;:;1`3:3a1gf72a;7g				<-------- original key
[+] a XORed with 3 = b						<-------- encoding operations
[+] g XORed with 3 = d
[+] 7 XORed with 3 = 4
[+] ` XORed with 3 = c
[+] 1 XORed with 3 = 2
[+] 2 XORed with 3 = 1
[+] 4 XORed with 3 = 7
[+] 5 XORed with 3 = 6
[+] 0 XORed with 3 = 3
[+] 4 XORed with 3 = 7
[+] a XORed with 3 = b
[+] ` XORed with 3 = c
[+] ; XORed with 3 = 8
[+] 1 XORed with 3 = 2
[+] ; XORed with 3 = 8
[+] : XORed with 3 = 9
[+] ; XORed with 3 = 8
[+] 1 XORed with 3 = 2
[+] ` XORed with 3 = c
[+] 3 XORed with 3 = 0
[+] : XORed with 3 = 9
[+] 3 XORed with 3 = 0
[+] a XORed with 3 = b
[+] 1 XORed with 3 = 2
[+] g XORed with 3 = d
[+] f XORed with 3 = e
[+] 7 XORed with 3 = 4
[+] 2 XORed with 3 = 1
[+] a XORed with 3 = b
[+] ; XORed with 3 = 8
[+] 7 XORed with 3 = 4
[+] g XORed with 3 = d
encoded key: bd4c217637bc828982c090b2de41b84d		<---------- final encoded key
try again!
```

Using this method, the key is successfully recovered.

### Conclusion

Though the example program was once again rather trivial for demonstration purposes, the utility of this technique is clear.
As long as the logic of an internal function can be recreated in a shared library, that internal function can be hooked and 
its behavior logged via redirect-to-PLT. This capability can be useful when examining functions that perform calculations,
encoding, or encryption internally.


### Links and References

 1. [Stack Frame Layout on x86-64](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64)
 2. [Extended ASM](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)
