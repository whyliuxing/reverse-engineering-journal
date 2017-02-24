Reverse_Engineering_Journal
===========================
I put anything I find interesting regarding reverse engineering in this journal. The date beside each heading denotes the start date that I added the topic, but most of the time I will still be adding bullets to that heading days later. 

Table of Contents 
=================
* [General Knowledge](#121816-general-knowledge)
* [[HARD TO REMEMBER] x86 Instructions With Side Effects](#122416-hard-to-remember-x86-instructions-with-side-effects)
* [Anti-Disassembly](#111716-anti-disassembly)
* [Anti-Debugging](#111716-anti-debugging)
* [Breakpoints](#12516-breakpoints)
* [String Encoding](#121216-string-encoding)
* [C++ Reversing](#121316-c-reversing)
* [64-Bit](#121416-64-bit)
* [Data Encoding](#121516-data-encoding)
* [Base64](#121516-base64)
* [Stripped Binaries](#121616-stripped-binaries)
* [LD_PRELOAD](#121616-ld_preload)
* [Random Number Generator](#121716-random-number-generator)
* [Useful Python for RCE](#122816-useful-python-for-rce)
* [ELF Files](#12017-elf-files)
* [Anti-Emulation](#252017-anti-emulation)
* [GDB](#21517-gdb)

## *12/18/16 General Knowledge*
* (Intel Specific) value stored in RAM is in little-endian but when moved to registers it is in big-endian  
* the 8 32-bit general-purpose registers(GPRs) for x86 architecture: eax, ebx, ecx, edx, edi, esi, ebp, and esp
* For x64 architecture, there are 18 general-purpose registers(GPRs)
* Calling Conventions(x86): 
 * CDECL: arguments pushed on stack from right to left. Caller cleaned up stack after
 * STDCALL: arguments pushed on stack from right to left. Callee cleaned up stack after
 * FASTCALL: first two arguments passed in ecx and edx. If there are more, they are pushed onto the stack
* The one byte nop instruction is an alias mnemonic for the xchg eax, eax instruction
* There is no way to tell the datatype of something stored in memory by just looking at the location of where it is stored. The datatype is implied by the operations that are used on it. For example, if an instruction loads a value into eax, comparison is taken place between eax and 0x10, and ja is used to jump to another location if eax is greater, then we know that the value is an unsigned int since ja is for unsigned numbers
* Thunk function: a small subroutine that assists a call to another subroutine. Thunk function can be used to get current instruction address then use it to reference a variable in the data section since data section is at a known offset from the code section. Example: __i686.get_pc_thunk.cx  
* (32 bits Windows exe) FS segment register points to the beginning of current Thread Environment Block (TEB), also know as Thread Information Block (TIB). Offset zero in TEB is the head of a linked list of pointers to exception handler functions on 32-bit system. Offset 30h is the PEB structure. Offset 2 in the PEB is the BeingDebugged field. In x64, PEB is located at offset 60h of the gs segment
* Any function that calls another function is called a non-leaf function, and all other functions are leaf functions
* Compress before you encrypt 

## *12/24/16 ([HARD TO REMEMBER] x86 Instructions With Side Effects)*
* IMUL reg/mem: register is multiplied with AL, AX, or EAX and the result is stored in AX, DX:AX, or EDX:EAX
* IDIV reg/mem: takes one parameter (divisor). Depending on the divisor’s size, div will use either AX, DX:AX, or EDX:EAX as the dividend, and the resulting quotient/remainder pair are stored in AL/AH, AX/DX, or EAX/EDX
* STOS: writes the value AL/AX/EAX to EDI. Commonly used to initialize a buffer to a constant value
* SCAS: compares AL/AX/EAX with data starting at the memory address EDI
* LODS: reads 1, 2, or 4 byte value from esi and stores it in al, ax, or eax 
* REP prefix: repeats an instruction up to ECX times
* MOVSB/MOVSW/MOVSD instructions move data with 1, 2, or 4 byte granularity between two addresses. They implicitly use EDI/ESI as the destination/source address, respectively. In addition, they also automatically update the source/destination address depending on the direction flag
* CLD: clear direction flag. DS: 0
* STD: set direction flag. DS: 1
* PUSHAD, POPAD: pushes/pops all 8 general-purpose registers 
* PUSHFD, POPFD: pushes/pops EFLAGS register 

## *11/17/16 (Anti-Disassembly)*
* __Linear disassembly__: disassembling one instruction at a time linearly. Problem: code section of nearly all binaries will also contain data that isn’t instructions 
* __Flow-oriented disassembly__: process false branch first and note to disassemble true branch in future. When it reaches a unconditional jump, it will add the dest to list of places to disassemble in future. It will then step back and disassemble from the list of places it noted previously. For call instruction, most will disassemble the bytes after the call first and then the called location. If there is conflict between the true and false branch when disassembling, disassembler will trust the one it disassembles first
* Use inline functions to obscure function declaration
* __Disassembly Desynchronization__: to cause disassembly analysis tools to produce an incorrect program listing. Works by taking advantage of the assumptions and limitations of disassemblers. For every assumption, there is a corresponding anti-disassembly technique. Desynchronization had the greatest impact on the disassembly, but it was easily defeated by reformatting the disassembly to reflect the correct instruction flow
  + __Jump instructions with the same target__: jz follows by jnz. Essentially an unconditional jump. The bytes following jnz instruction could be data but will be disassembled as code
  + __Jump instructions with a constant condition__: xor follows by jz. It will always jump so bytes following false branch could be data
  + __Impossible disassembly__: A byte is part of multiple instructions. No disassembler will represent a byte as part of two instructions, but the processor has no such limitation
* __Opcode Obfuscation__: a more effective technique for preventing correct disassembly by encoding or encrypting the actual instructions
  + Encoding portions of a program has the dual effect of hindering static analysis because disassembly is not possible and of hindering debugging because placing breakpoints is difficult. Even if the start of each instructions is known, breakpoints cannot be placed until instructions have been decoded
  + Virtual obfuscation
* __Function pointer problem__: if a function is called indirectly through pointers, ida pro xref only record the first usage
* __Return pointer abuse__: ret instruction is used to jump to function instead of returning from function. Disassembler doesn’t show any code cross-reference to the target being jumped to. Also, disassembler will prematurely terminate the function
* __Thwarting stack-frame analysis__: technique to mess with ida pro when deducing numbers of param and local variables. Make a conditional jump that always false but in true branch add absurd amount to esp
* __Dynamically Computed Target Addresses__: an address to which execution will go to is computed at runtime. The intent is to hide control flow from static analysis
* More complex control flow hiding: program uses multiple threads or child processes to compute control flow information and receive that information via interprocess communication (for child processes) or synchronization primitives (for multiple threads)
* __Tampering/Removing Section Headers (ELF)__: makes tools such as gdb and objdump useless since they rely on the section headers to locate symbol info. Segments are necessary for program execution, not sections. Section header table is for linking and debugging.  
* __Imported Function Obfuscation (makes it difficult to determine which shared lib or lib func are used)__: have the program’s import table be initialized by the program itself. The program itself loads any additional lib it depends on, and once the lib are loaded, the program locates any required functions within those lib
  + (Windows) use LoadLibrary function to load required lib by name and then perform function address lookups within each lib using GetProcAddress

## *11/17/16 (Anti-Debugging)*
* For Linux Only: This is an elegant technique to detect if a debugger or program tracer such as strace or ltrace is being used on the target program. The premise of this technique is that a ptrace[PTRACE_TRACEME] cannot be called in succession more than once for a process. All debuggers and program tracers use this call to setup debugging for a process
* Self-Debugging (Window’s version of ptrace): main process spawns a child process that debugs the process that created the child process, which prevents debugger from attaching to the same process. This can be bypassed be setting the EPROCESS->DebugPort (the EPROCESS structure is a struct returned by the kernel mode function PsGetProcessId) field to 0
* Windows API provides several functions that can be used by a program to determine if it is being debugged (e.g. isDebuggerPresent)
* Several flags within the PEB structure provide information about the presence of a debugger
* Location of PEB can be referenced by the location fs:[30h]. The second item on the PEB struct is BYTE BeingDebugged. The API function, isDebuggerPresent, checks this field to determine if a debugger is present or not
* __ProcessHeap Flag__: within Reserved4 array in PEB, is ProcessHeap, which is set to location of process’s first heap allocated by loader. This first heap contains a header with fields that tell kernel whether the heap was created within a debugger. The fields are Flags and ForceFlags. If the Flags field does not have the HEAP_GROWABLE(0x2) flag set, then the process is being debugged. Also, if ForceFlags != 0, then the process is being debugged
* __NTGlobalFlag__: Since processes run slightly differently when started with a debugger, they create memory heaps differently. The information that the system uses to determine how to create heap structures is stored in the NTGlobalFlag field in the PEB at offset 0x68 in x86 and 0xbc in x64. If value at this location is 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK(0x10) | FLG_HEAP_ENABLE_FREE_CHECK(0x20) | FLG_HEAP_VALIDATE_PARAMETERS(0x40)), we know that we are running in debugger
* __INT Scanning__: Search the .text section for the 0xCC byte. If it exists, that means that a soft breakpoint has been set and the process is under a debugger 
* __Code Checksums__:  Instead of scanning for 0xCC, this check simply performs a cyclic redundancy check (CRC) or a MD5 checksum of the opcodes in the malware
* __Hardware Breakpoints__: Get a handle to current thread using GetCurrentThread(). Get registers of current thread using GetThreadContext(). Check if registers DR0-DR3 is set, if it is then there are hardware breakpoints set  
* __False Breakpoints and SIGTRAP Handler__: (Linux) a breakpoint is created by overwriting the first byte of instruction with an int3 opcode (0xcc). To setup a false breakpoint then we simply insert int3 into the code. This raises a SIGTRAP when int3 is executed. If our code has a signal handler for SIGTRAP, the handler will be executed before resuming to the instruction after int3. But if the code is under the debugger, the debugger will catch the SIGTRAP signal instead and might not pass the signal back to the program, resulting in the signal handler not being executed 
* __Trap Flag Check__: (Windows) Trap Flag is part of the EFLAGS register. IF TF is 1, CPU will generate Single Step exception(int 0x01h) after executing an instruction. Trap Flag can be manually set to cause next instruction to raise an exception. If the process is running under a debugger, the debugger will not pass the exception to the program so the exception handler will never be ran
* __Timing Checks__:  record a timestamp, perform some operations, take another timestamp, and then compare the two timestamps. If there is a lag, you can assume the presence of a debugger
* __rdtsc Instruction (0x0F31)__: this instruction returns the count of the number of ticks since the last system reboot as a 64-bit value placed into EDX:EAX. Simply execute this instruction twice and compare the difference between the two readings
* __TLS Callbacks__: (Windows only) Most debuggers start at the program’s entry point as defined by the PE header. TlsCallback is traditionally used to initialze thread-specific data before a thread runs, so TlsCallback is called before the entry point and therefore can execute secretly in a debugger. To make it harder to find anti-debugging checks, anti-debugging checks can be placed in TlsCallback
* __/proc/self/status File__: (Linux only) a dynamic file that exists for every process. It includes information on whether a process is being traced

## *12/5/16 (Breakpoints)*
* Software breakpoint: debugger read and store the first byte of instruction and then overwrite that first byte with 0xcc (int 3). When CPU hits the breakpoint, SIGTRAP signal is raised, process is stopped, and internal lookup occurs and the byte is flipped back
* Hardware breakpoints are set at CPU level, in special registers called debug registers (DR0 through DR7)
 * Only DR0 - DR3 registers are reserved for breakpoint addresses
 * Before the CPU attempts to execute an instruction, it first checks to see whether the address is currently enabled for a hardware breakpoint. If the address is stored in debug registers DR0–DR3 and the read, write, or execute conditions are met, an INT1 is fired and the CPU halts
 * Can check if someone sets a hardware breakpoint by using GetThreadContext() and checks if DR0-DR3 is set
* When a debugger is setting a memory breakpoint, it is changing the permissions on a region, or page, of memory
 * Guard page: Any access to a guard page results in a one-time exception, and then the page returns to its original status. Memory breakpoint changes permission of the page to guard

## *12/12/16 (String Encoding)*
* There are only 128 characters defined in ASCII and 95 of them are human-readable
* ASCII only used 7 bits, but the extra bit is still not enough to encode all the other languages
* Various encoding schemes were invented but none covered every languages until Unicode came along
* Unicode is a large table mapping characters to numbers (or a table of code points for characters) and the different UTF encodings specify how these numbers are encoded as bits
* Characters are referred to by their “Unicode code point”
* The primary cause of garbled text is: Somebody is trying to read a byte sequence using the wrong encoding
* All characters available in the ASCII encoding only take up a single byte in UTF-8 and they're the exact same bytes as are used in ASCII. In other words, ASCII maps 1:1 unto UTF-8. Any character not in ASCII takes up two or more bytes in UTF-8

## *12/13/16 (C++ Reversing)*
* Ecx is used to stored the this pointer. Sometimes esi
* Class member functions are called with the usual function parameters in the stack and with ecx pointing to the class’s object 
* Class’s object in assembly only contains the vfptr (pointer to virtual functions table) and variables. Member functions are not part of it
* Memory spaces for global objects are allocated at compile-time and placed in data or bss section of binary 
* Use Name Mangling to support Method Overloading (multiple functions with same name but accept different parameters) since in PE format function is only labeled with its name 
* Child class automatically has all functions and data from parent class
* Execution for virtual function is determined at runtime. Function call is indirect (through a register)

## *12/14/16 (64-Bit)*
* All addresses and pointers are 64 bits
* All general-purpose registers have increased in size, tho 32-bit versions can still be accessed
* Some general-purpose registers (RDI, RSI, RBP, and RSP) supports byte accesses
* There are twice as many general-purpose registers. The new one are labeled R8 - R15
* DWORD (32-bit) version can be accessed as R8D. WORD (16-bit) version are accessed with a W suffix like R8W. Byte version are accessed with an L suffix like R8L
* Supports instruction pointer-relative addressing. Unlike x86, referencing data will not use absolute address but rather an offset from RIP
* Calling conventions: first 4 parameters are placed in RCX, RDX, R8, and R9. Additional one are stored on stack
* In 32-bit code, stack space can be allocated and unallocated in middle of the function using push or pop. However, in 64-bit code, functions cannot allocate any space in the middle of the function
* Nonleaf functions are sometimes called frame functions because they require a stack frame. All nonleaf functions are required to allocate 0x20 bytes of stack space when they call a function. This allows the function being called to save the register parameters (RCX, RDX, R8, and R9) in that space. If a function has any local stack variables, it will allocate space for them in addition to the 0x20 bytes
* Structured exception handling in x64 does not use the stack. In 32-bit code, the fs:[0] is used as a pointer to the current exception handler frame, which is stored on the stack so that each function can define its own exception handler
* Easier in 64-bit code to differentiate between pointers and data values. The most common size for storing integers is 32 bits and pointers are always 64 bits

## *12/15/16 (Data Encoding)*
* All forms of content modification for the purpose of hiding intent
* Caesar cipher: formed by shifting the letters of alphabet #’s characters to the left or right
* Single-byte XOR encoding: modifies each byte of plaintext by performing a logical XOR operation with a static byte value
* Problem with Single-byte XOR is that if there are many null bytes then key will be easy to figure out since XOR-ing nulls with the key reveals the key. Solutions: 
  + Null-preserving single-byte XOR encoding: if plaintext is NULL or key itself, then it will not be encoded via XOR
  + Blum Blum Shub pseudo-random number generator: Produces a key stream which will be xor-ed with the data. Generic form: Value = (Value * Value) % M. M is a constant and an initial V needs to be given. Actual key being xor-ed with the data is the lowest byte of current PRNG value
* Identifying XOR loop: looks for a small loop that contains the XOR function (where it is xor-ing a register and a constant or a register with another register)
* Other Simple Encoding Scheme:
  + ADD, SUB
  + ROL, ROR: Instructions rotate the bits within a byte right or left
  + Multibyte: XOR key is multibyte
  + Chained or loopback: Use content itself as part of the key. EX: the original key is applied at one side of the plaintext, and the encoded output character is used as the key for the next characte
* If outputs are suspected of containing encoded data, then the encoding function will occur prior to the output. Conversely, decoding will occur after an input

## *12/15/16 (Base64)*
* Used to represent binary data in ASCII string format
* It converts binary data into a limited character set of 64 characters
* Most common character set is MIME’s Base64, which uses A-Z, a-z, and 0-9 for the first 62 values and + / for the last two
* Bits are read in blocks of six. The number represented by the 6 bits is used as an index into a 64-byte long string
* One padding character may be presented at the end of the encoded string (typically =). If padded, length of encoded string will be divisible by 4
* One beautiful thing about Base64 is how easy it is to develop a custom substitution cipher since the only item that needs to be changed is the indexing string

## *12/16/16 (Stripped Binaries)*
* There are 2 sections that contain symbols: .dynsym and .symtab. .dynsym contains dynamic/global symbols, those symbols are resolved at runtime. .symtab contains all the symbols. Since they are not necessary for runtime, they are not loaded into memory 
* nm command to list all symbols in the binary from .symtab
* Stripped binary == no .symtab symbol table
* .dynsym symbol table cannot be stripped since it is needed for runtime, so imported library symbols remain in a stripped binary. But if a binary is compiled statically, it will have no symbol table at all if stripped
* With non-stripped, gdb can identify local function names and knows the bounds of all functions so we can do: disas "function name"
* With stripped binary, gdb can’t even identify main. Can identify entry point using the command: info file. Also, can’t do disas since gdb does not know the bounds of the functions so it does not know which address range should be disassembled. Solution: use examine(x) command on address pointed by pc register like: x/14i $pc

## *12/16/16 (LD_PRELOAD)*
* When you start a dynamically linked program, it doesn’t have all the code for the functions it needs. So this is what happened: 
  + The program gets loaded into memory
  + The dynamic linker figures out which other libraries that program needs to run (.so files)
  + It loads them into memory 
  + It connects everything up 
* LD_PRELOAD is an environment variable that says “whenever you look for a function name, look in me first”

## *12/17/16 (Random Number Generator)*
* Randomness requires a source of entropy, which is a sequence of bits that is unpredictable. This source of entropy can be from OS observing its internal operations or ambient factors
* This source of entropy is call the seed
* Algorithms using OS's internal operations or ambient factors as seed are known as pseudorandom generators, because while their output isn't random, it nonetheless passes statistical tests of randomness. As long as you seed them with a legitimate source of entropy, they can generate fairly long sequences of random values without the sequence repeating

## *12/28/16 (Useful Python for RCE)*
* chr: hex/int to ASCII
* ord: ASCII to hex
* Struct module: pack python objects as contiguous chunk of bytes or disassemble a chunk of bytes to python structures
* int.from_bytes(bytes, byteorder): return integer represented by the array of bytes
* int.to_bytes(bytes, byteorder): return array of bytes representing an integer
* hex() returns a string
* bytes is an immutable sequence of bytes. bytearray is mutable

## *1/20/17 (ELF Files)*
* ELF file header starts at offset 0 and is the roadmap that describes the rest of the file. It marks the ELF type, architecture, execution entry point, and offsets to program headers and section headers
* Program header table let the system knows how to create the process image. It contains an array of structures, each describing a segment. A segment contains one or more sections
* Section header table is not necessary for program execution. It is mainly for linking and debugging purposes. It is an array of ELF_32Shdr or ELF_64Shdr structures (Section Header)
* Relocatable objects have no program headers since they are not meant to be loaded into memory directly
* .got (Global Offset Table) section: a table of addresses located in the data section. It allows PIC code to reference data that were not available during compilation (ex: extern "var"). That data will have a section in .got, which will then be filled in later by the dynamic linker
* .plt (Procedure Linkage Table) section: a part of the text section, consisting of external function entries. Each plt entry has a correcponding entry in .got.plt which contains the actual offset to the function. Resolving of external functions is done through lazy binding. It means that it doesn't resolve the address until the function is called. 
* plt entry consists of: 
  + A jump to an address specified in GOT
  + argument to tell the resolver which function to resolve (only reach there during function's first invocation)
  + call the resolver (resides at PLT entry 0)
* .got.plt section: contains dynamically-linked function entries that can be resolved lazily

## *2/5/2017 (Anti-Emulation)*
* allows reverse engineer to bypass many anti-debugging techniques
* __Detection through Syscall__: invoke various uncommon syscalls and check if it contains expected value. Since there are OS features not properly implemented, it means that the process is running under a debugger
* __CPU Inconsistencies Detection__: try executing privileged instructions in user mode. If it succeeded, then it is under emulation
* __Timing Delays__: execution under emulation will be slower than running under real CPU

## *2/15/17 (GDB)*
* x command displays memory contents at a given address in the specified format 
* p command displays value stored in a named variable
* To look at instructions starting from pc for stripped binary in gdb: x/14i $pc
* Set hardware breakpoint in GDB: hbreak 
* Set watchpoint in GDB: watch only break on write, rwatch break on read, awatch break on read/write
* ASLR is turned off by default in GDB. To turn it on: set disable-randomization off
* Default display assembly in AT&T notation. To change it to the more readable Intel notation: set disassembly-flavor intel. To make this change permanent, write it in the .gdbinit file

[Go to Top](#table-of-contents-)
