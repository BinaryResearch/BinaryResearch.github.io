---
layout: post
title: A Technique for Hooking Internal Functions of Dynamically-Linked ELF Binaries
tags: [hooking, reverse-engineering, instrumentation, debugging, ELF, LD_PRELOAD, redirect-to-PLT, AMD64, x86-64, PIE]
author-id: julian
---

It is well known that `LD_PRELOAD` can be used to override shared library
functions loaded at runtime by the dynamic linker [1]. What is not so well known is
that *internal functions* - functions whose code lies within the `.text` section
of the binary - can also be be hooked indirectly using a simple trick that relies on `LD_PRELOAD`, even though 
these functions obviously are not imported from dynamically-linked libraries 
(shared objects).


### Overview

The following will be discussed:
 - a discription of redirect-to-PLT
 - use cases
 - redirect-to-PLT is not GOT/PLT hooking or infection
 - demonstration of the technique with toy program

Prerequisites:
 - basic familiarity with the following:
   - the ELF format
   - dynamic linking in Linux
   - `LD_PRELOAD` - what it is, how to use it

Tools:
 - Keystone Engine
 - Python 3
 - GCC
 
# Introduction

When a function in the `.text` section is called, the instruction pointer jumps
to the address of the first instruction of that function. To hook such a function,
the instruction pointer can be redirected to jump to the entry in the
Procedure Linkage Table (PLT) of a shared library function which will be called
instead. This shared library function can then be overridden via `LD_PRELOAD` to
inject a custom shared library function which contains the code to be executed 
in place of the hooked internal function. Crucially, even though this code is 
called from within a shared library that is used elsewhere in the program and called under different
conditions from the hooked internal function, it is possible to control when this 
code executes.

Put simply, this technique is essentially an extension of the `LD_PRELOAD` 
technique such that it can be used to override internal functions as well,
wherein flow of execution detours from code resident in the binary's 
`.text` section to code imported from an injected shared library. It consists
of a redirect and an override:

  1. First, the call to the target internal function is replaced via patching 
     with a call to a shared library function in the PLT.
  2. Next, that particular shared library function is overridden with code from
     a custom shared library, and that shared library is loaded via `LD_PRELOAD`

### Use Cases

Redirect-to-PLT may be useful when there is a need to insert debugging instrumentation into internal 
functions or if we want to override an internal function, but adding code to the 
binary itself is not desirable.
   - code may be added to a binary by adding a new segment or via segment padding 
     infection techniques [3][4], but this is quite cumbersome for a few reasons:
      - adding code this way usually requires re-engineering the binary file
         to some extent, extending or adding segments, changing flags, updating 
         information in the ELF header and the program load table to reflect 
         changes made to the binary image and so forth.
      - calling shared library functions in code added to the binary is rather
	 complex, thus system calls are typically made directly. This often 
         necessitates writing code in assembly rather than C or using both 
         together.

     As a result of the restructions imposed by this approach, it is not very
     flexible and writing code to accomplish this appears to be a comapratively 
     slow and error-prone endeavor.

   - However, if we want to analyze the behavior of an internal function using the redirect-to-PLT trick, we can recreate the
     logic of the function in a shared library, add the desired modifications, patch
     the code to call that new shared library function instead of the chosen internal function, 
     and then inject this shared library with `LD_PRELOAD`. The instrumented 
     code in this shared library will then be executed instead of the original 
     internal function code.

### Hooking with redirect-to-PLT vs GOT/PLT hooking

It should be noted that even though this method relies on the PLT for redirection, 
it is not related to GOT/PLT hooking [2], in which the GOT or PLT are overwritten
in order to override imported shared library functions in a similar vein to 
`LD_PRELOAD`. This *redirect-to-PLT* trick is a hack to override *internal 
functions* specifically; no changes are made to the GOT or the PLT.


# Overriding an Internal Function in a Toy Program

For the following program (`example_program1`), we want to hook the `detour_me()` function:

<script src="https://gist.github.com/BinaryResearch/10b567cb594d49bc5c897434fcb3bc9b.js"></script>

This produces the following ouput:

```shell
$ ./example_program_1 
In main(), before detour_me()
Can you detour this function?
In main(), after detour_me()
```

The approach to hooking this function is as follows:
 1. Select a suitable shared library function to override
 2. Patch the `CALL` to `detour_me()` to point to the PLT entry of the chosen shared
    library function
 3. Design the custom shared library to inject
 4. Use `LD_PRELOAD` to inject the shared library. In this case the hook will print
    "I <3 LD_PRELOAD".

**Before beginning, a copy of the original binary should be made. Here the copy
will be called `copy_to_patch`. Subsequent steps will involve this copy, not
the original binary.**

To select a suitable shared library function to override, we can examine which
shared library functions have entries in the PLT. One way of doing this is using `grep` to
search through disassembly of the binary output by `objdump`:

```shell
$ objdump -dj .text copy_to_patch | grep plt
 65e:	e8 0d ff ff ff       	callq  570 <__cxa_finalize@plt>
 69a:	e8 c1 fe ff ff       	callq  560 <printf@plt>
 6ab:	e8 b0 fe ff ff       	callq  560 <printf@plt>
 6bc:	e8 9f fe ff ff       	callq  560 <printf@plt>
 6cd:	e8 8e fe ff ff       	callq  560 <printf@plt>
 6d9:	e8 72 fe ff ff       	callq  550 <puts@plt>
 6ec:	e8 5f fe ff ff       	callq  550 <puts@plt>
 6fd:	e8 4e fe ff ff       	callq  550 <puts@plt>

```
Since this example program is trivial, we could override any of these, but here
`__cxa_finalize()` will be chosen since it illustrates the flexibility of this
approach and will also introduce an interesting challenge associated with using this
technique.

Next, the call to `detour_me()` needs to be patched to point to the entry in the
PLT for `__cxa_finalize()`. From the bit of output above, it can be seen that the file offset
of the the PLT entry for `__cxa_finalize()` is 0x570. According to the disassembly
of `main()`, `detour_me()` is called at file offset 0x6f1:

```shell
00000000000006e1 <main>:
 6e1:   55                      push   %rbp
 6e2:   48 89 e5                mov    %rsp,%rbp
 6e5:   48 8d 3d ca 00 00 00    lea    0xca(%rip),%rdi        # 7b6 <_IO_stdin_used+0x26>
 6ec:   e8 5f fe ff ff          callq  550 <puts@plt>
 6f1:   e8 94 ff ff ff          callq  68a <detour_me>   <----------------
 6f6:   48 8d 3d d7 00 00 00    lea    0xd7(%rip),%rdi        # 7d4 <_IO_stdin_used+0x44>
 6fd:   e8 4e fe ff ff          callq  550 <puts@plt>
 702:   b8 00 00 00 00          mov    $0x0,%eax
 707:   5d                      pop    %rbp
 708:   c3                      retq   
 709:   0f 1f 80 00 00 00 00    nopl   0x0(%rax)
```

Key pieces of information for patching:

 - `main()` calls `detour_me()` at offset 0x6f1
 - the PLT entry for `__cxa_finalize()` is at 0x570

Python script to patch the copy of the example program:

<script src="https://gist.github.com/BinaryResearch/e70d29e2d3e36f9967fe7d0c64cb1841.js"></script>

After the patch is applied, `__cxa_finalize()` is called from `main()` instead of `detour_me()`:
 
```shell
00000000000006e1 <main>:
 6e1:   55                      push   %rbp
 6e2:   48 89 e5                mov    %rsp,%rbp
 6e5:   48 8d 3d ca 00 00 00    lea    0xca(%rip),%rdi        # 7b6 <_IO_stdin_used+0x26>
 6ec:   e8 5f fe ff ff          callq  550 <puts@plt>
 6f1:   e8 7a fe ff ff          callq  570 <__cxa_finalize@plt>   <--------------
 6f6:   48 8d 3d d7 00 00 00    lea    0xd7(%rip),%rdi        # 7d4 <_IO_stdin_used+0x44>
 6fd:   e8 4e fe ff ff          callq  550 <puts@plt>
 702:   b8 00 00 00 00          mov    $0x0,%eax
 707:   5d                      pop    %rbp
 708:   c3                      retq   
 709:   0f 1f 80 00 00 00 00    nopl   0x0(%rax)

```

Now that the binary has been patched, it is time to write a shared library to
inject. Fortunately, in this case the logic of the program is very simple and
the library function chosen to be overridden can simply be substituted. We need
not concern ourselves with wrapping it.

Here is the code of the custom shared library to inject:

<script src="https://gist.github.com/BinaryResearch/14348015a7e62bd6619f68e04ef172ed.js"></script>

This will be compiled via

```shell
$ gcc -shared -fPIC -o override_cxa_finalize.so override_cxa_finalize.c 
```

Now we are ready to inject the code!

```shell
$ LD_PRELOAD=$PWD/override_cxa_finalize.so ./copy_to_patch 
In main(), before detour_me()
I <3 LD_PRELOAD
In main(), after detour_me()
I <3 LD_PRELOAD
I <3 LD_PRELOAD
```

It works, but there is a problem: `__cxa_finalize()` is called 3 times, whereas
in the original binary the function we want to hook, `detour_me()`, is called
only once. How can we ensure that the detour for `detour_me()` is executed **only**
when `__cxa_finalize()` is called from `main()`? 

This is one of the main challenges associated with using
a library function to hook an internal function; depending on which library function
is chosen, it may be called an arbitrary number of times and across a variety of
circumstances which may be hard or impossible to predict or account for. 

In this case, one possible solution is to take advantage of the fact that according to the prototype for
`__cxa_finalize()`, the function takes an argument and that the value of this argument
will vary across calls to `__cxa_finalize()`. The code overriding `detour_me()`
can be set to execute for a particular value of the argument.

<script src="https://gist.github.com/BinaryResearch/4ebb6c2dca3f725ba05414e30c44598e.js"></script>

This produces the desired behavior:

```shell
$ LD_PRELOAD=$PWD/override_cxa_finalize_A.so ./copy_to_patch 
In main(), before detour_me()
Argument to __cxa_finalize(): 0x1
I <3 LD_PRELOAD
In main(), after detour_me()
Argument to __cxa_finalize(): 0x556fdf12d008
Argument to __cxa_finalize(): 0x7f22c14cb028
```

Another option is counting the number of times `__cxa_finalize()` is called so that the
"I <3 LD_PRELOAD" message is printed only when `detour_me()` is being hooked. 
Aside from the very first call to `__cxa_finalize()`, we do not want our code for
`detour_me()` to execute. Therefore,
if the number of times `__cxa_finalize()` has been called can be checked *within*
`__cxa_finalize()`, the code overriding `detour_me()` can be made to execute *only*
upon the first call to `__cxa_finalize()` and otherwise not.

This can be accomplished by using `setenv()` and `getenv()` within the injected shared library
to create, update and read an
environmental variable stored on the stack that keeps track of the number of times `__cxa_finalize()` is called during program runtime:

<script src="https://gist.github.com/BinaryResearch/6721ab6e867e8837752000a64fa23dce.js"></script>

And inject the new library:
```shell
$ LD_PRELOAD=$PWD/override_cxa_finalize_B.so ./copy_to_patch 
In main(), before detour_me()
__cxa_finalize() called 1 time!
I <3 LD_PRELOAD
In main(), after detour_me()
__cxa_finalize() called 2 times!
__cxa_finalize() called 3 times!
```

Once again, the code for `detour_me()` in the injected library  is executed 
only when `__cxa_finalize()` is called in `main()` in place of `detour_me()`.


# Conclusion

 - By patching a function call to an internal function to jump to a shared library
   function entry in the PLT, that shared library function will be called instead 
   of the internal function. Thus the internal function is now hooked by a shared
   library function.
 - The shared library function that hooks the internal function can be overridden 
   with a custom library via `LD_PRELOAD`.
 - Since execution detours to the shared library function, there are few constraints
   on what can be executed instead of the code of the internal function. For example,
   unlike when inserting code into the binary itself, 
   library calls can be made easily, and space is a non-factor. There is no need to
   use code caves, look for `00` padding, extend segments, update variable relocations manually, etc.
 - However, ensuring that the code overriding the internal function is executed
   only when that internal function is hooked by the shared library function may require
   coding triggers in the custom shared library, depending on which library function was chosen as the
   internal function override;
   program- and runtime-specific conditions may be very particular.

In this post, a toy example was used to introduce this technique. In the next part,
it will be demostrated how to use redirect-to-PLT to insert debugging instrumentation into the internal functions of crackme programs. 


### Links and References

 1. [Dynamic linker tricks: Using LD_PRELOAD to cheat, inject features and investigate programs](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/)
 2. [SHARED LIBRARY CALL REDIRECTION VIA ELF PLT INFECTION](http://phrack.org/issues/56/7.html)
 3. [Infecting the plt/got](https://lief.quarkslab.com/doc/latest/tutorials/05_elf_infect_plt_got.html) 
 4. [UNIX VIRUSES](https://www.win.tue.nl/~aeb/linux/hh/virus/unix-viruses.txt)
