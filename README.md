# <p align='center'> Reverse Engineering Journal </p>
I put anything I find interesting regarding reverse engineering in this journal. The date beside each heading denotes the start date that I added the topic, but most of the time I will still be adding information to that heading days later. 

# .table-of-contents

* [.general-knowledge](#general-knowledge)
  + [int 0x7374617274](#-int-0x7374617274-12182016-)
* [.tools](#tools)
  + [IDA Tips](#-ida-tips-412017-)
  + [GDB Tips](#-gdb-tips-21517-)
  + [WinDBG Tips](#-windbg-562017-)
* [.instruction-sets](#instruction-sets)
  + [x86](#-x86-4232017-)
  + [x86-64](#-x86-64-4242017-)
  + [ARM](#-arm-4142017-)
* [.languages](#languages)
  + [C++ Reversing](#-c-reversing-121316-)
  + [Python Reversing](#-python)
* [.file-formats](#file-formats)
  + [ELF Files](#-elf-files-12017-)
  + [PE Files](#-pe-files)
* [.operating-system-concepts](#operating-system-concepts)
  + [Windows OS](#-windows-os-412017-)
  + [Interrupts](#-interrupts-4132017-)
* [.anti-reversing](#anti-reversing)
  + [Anti-Disassembly](#-anti-disassembly-111716-)
  + [Anti-Debugging](#-anti-debugging-111716-)
  + [Anti-Emulation](#-anti-emulation-252017-)
* [.encodings](#encoding)
  + [String Encoding](#-string-encoding-121216-)
  + [Data Encoding](#-data-encoding-121516-)
---

# .general-knowledge

## *<p align='center'> int 0x7374617274 (12/18/2016) </p>*
* Processes are containers for execution. Threads are what the OS executes
* Any function that calls another function is called a non-leaf function, and all other functions are leaf functions
* Entry point of a binary (beginning of .text section) is not main. A program's startup code (how main is called) depends on the compiler and the platform that the binary is compiled for
* To hide a string from strings command, construct the string in code. So instead of the string being referenced from the .data section, it will be constructed in the .text section. To do this, initialize a string as an array of characters assigned to a local variable. This will result in code that moves each character onto the stack one at a time. To make the character harder to recognize, check out Data Encoding section in this journal
* __Random Number Generator__: Randomness requires a source of entropy, which is an unpredictable sequence of bits. This source of entropy is called the seed and can be from OS observing its internal operations or ambient factors. Algorithms using OS's internal operations or ambient factors as seed are known as pseudorandom generators, because while their output isn't random, it still passes statistical tests of randomness. So as long as you seed the algorithms with a legitimate source of entropy, they can generate fairly long sequences of random values without the sequence repeating 
* __Software/Hardware/Memory Breakpoint__: 
  * __Software Breakpoint__: debugger reads and stores the first byte of instruction and then overwrites that first byte with 0xCC (INT3). When CPU hits the breakpoint, OS kernel sends SIGTRAP signal to process, process execution is paused, and internal lookup occurs to flip the original byte back
  * __Hardware Breakpoint__: set in special registers called debug registers (DR0 through DR7)
    + Only DR0 - DR3 registers are reserved for breakpoint addresses
    + Before CPU attempts to execute an instruction, it first checks whether the address is currently enabled for a hardware breakpoint. If the address is stored in debug registers DR0–DR3 and the read, write, or execute conditions are met, an INT1 is fired and the CPU halts
    + Can check if someone sets a hardware breakpoint on Windows by using GetThreadContext() and checks if DR0-DR3 is set
  * __Memory Breakpoint__: changes the permissions on a region, or page, of memory
    + Guard page: Any access to a guard page results in a one-time exception, and then the page returns to its original status. Memory breakpoint changes permission of the page to guard
* __Virtual Address(VA) to File Offset Translation__: file_offset = VA - image_base - section_base_RVA + section_file_offset
  * VA - image_base = RVA. VA relative to the base of the image 
  * RVA - section_base_RVA = offset from base of the section
  * offset_from_section_base + section_file_offset = file offset on disk  
---

# .tools

## *<p align='center'> IDA Tips (4/1/2017) </p>*
* __Import Address Table (IAT)__: shows you all the dynamically linked libraries' functions that the binary uses. Import Address Table is important for a reverser to understand how the binary is interacting with the OS. To hide APIs call from displaying in the Import Address Table, a programmer can dynamically resolve the API 
  + How to find dynamically resolved APIs: get the binary's function trace (e.g. hybrid-analysis (Windows sandbox), ltrace). If any of the APIs it called is not in the Import Address Table, then that API is dynamically resolved. Once you find a dynamically resolved API, you can place a breakpoint on the API in IDA's debugger view (go to Module Windows, find the shared library the API is under, click on the library and another window will open showing all the available APIs, find the API that you are interested in, and place a breakpoint on it) and then step back through the call stack to find where it's called in user code after execution pauses at that breakpoint
* When IDA loads a binary, it simulates a mapping of the binary in memory. The addresses shown in IDA are the virtual memory addresses and not the offsets of binary file on disk
* To show advanced toolbar: View -> Toolbars -> Advanced Mode
* To save memory snapshot from your debugger session: Debugger -> Take Memory Snapshot -> All Segments
* Useful shortcuts: 
  + u to undefine 
  + d to turn it to data 
  + c to turn it to code 
  + g to bring up the jump to address menu
  + n to rename
  + x to show cross-references
#
## *<p align='center'> GDB Tips (2/15/17) </p>*
* ASLR is turned off by default in GDB. To turn it on: set disable-randomization off
* Default display assembly in AT&T notation. To change it to the more readable and superior Intel notation: set disassembly-flavor intel. To make this change permanent, write it in the .gdbinit file
* __Hooks__: user-defined command. When command ? is ran, user-defined command 'hook-?' will be executed (if it exists)
  + When reversing, it could be useful to hook on breakpoints by using hook-stop 
  + How to define a hook: 
    * (gdb) define hook-?
    * <div>>...commands...</div>
    * <div>>end</div>
    * (gdb)
* maint info sections: shows where sections are mapped to in virtual address space
* i command displays information on the item specified to the right of it
  + i proc mappings: show mapped address spaces 
  + i b: show all breakpoints 
  + i r: show the values in registers at that point of execution
* x command displays memory contents at a given address in the specified format
  + Since disas command won't work on stripped binary, x command can come in handy to display instructions from current program counter: x/14i $pc
* p command displays value stored in a named variable
* Set hardware breakpoint in GDB: hbreak 
* Set watchpoint (data breakpoint) in GDB: watch only break on write, rwatch break on read, awatch break on read/write
* Set temporary variable: set $<-variable name-> = <-value->
  * Set command can be used to change the flags in EFLAGS. You just need to know the bit position of the flag you wanted to change 
    + For example to set the zero flag, first set a temporary variable: set $ZF = 6 (bit position 6 in EFLAG is zero flag). Use that variable to set the zero flag bit: set $eflags |= (1 << $ZF)
    + To figure out the bit position of a flag that you are interested in, check out this image below:
    
<p align='center'> <img src="http://css.csail.mit.edu/6.858/2013/readings/i386/fig2-8.gif"> </p> 
<!-- EFLAGS Register - MIT course 6.858 --!>

#
## *<p align='center'> WinDBG Tips (5/6/17) </p>*
* 
---

# .instruction-sets

## *<p align='center'> x86 (4/23/2017) </p>*
* Value stored in RAM is in little-endian but when moved to registers it is in big-endian  
* The 8 32-bit general-purpose registers (GPRs) for x86 architecture: EAX, EBX, ECX, EDX, EDI, ESI, EBP, and ESP. GPRs are used for temporary storage and can be directly accessed/changed in user code (e.g. mov eax, 1)  
* The 5 32-bit memory index registers for x86 architecture: ESI, EDI, ESP, EBP, EIP. Most of them are also GPRs. They usually contain memory addresses. But obviously, if a memory index register is used as a GPR instead, it can contain any value 
* The 6 32-bit selector registers for x86 architecture: CS, DS, ES, FS, GS, SS. A selector register indicates a specific block of memory from which one can read or write. The real memory address is looked up in an internal CPU table 
  + Selector registers usually points to OS specific information. For example, FS segment register points to the beginning of current Thread Environment Block (TEB), also know as Thread Information Block (TIB), on Windows. Offset zero in TEB is the head of a linked list of pointers to exception handler functions on 32-bit system. Offset 30h is the PEB structure. Offset 2 in the PEB is the BeingDebugged field. In x64, PEB is located at offset 60h of the gs segment register
* The 3 32-bit scratch registers for x86 architecture: EAX, ECX, and EDX. Values stored in scratch registers are not preserved across function calls. It allows process to spend less time on saving registers that are most likely to be modified 
* Control register: EFLAGS. EFLAGS is a 32-bit register. It contains values of 32 boolean flags that indicate results from executing the previous instruction. EFLAGS is used by JCC instructions to decide whether to jump or not
* Calling Conventions (x86): 
  + CDECL: arguments pushed on stack from right to left. Caller cleaned up stack after
  + STDCALL: arguments pushed on stack from right to left. Callee cleaned up stack after
  + FASTCALL: first two arguments passed in ECX and EDX. If there are more, they are pushed onto the stack
* The call instruction contains a 32-bit signed relative displacement that is added to the address immediately following the call instruction to calculate the call destination
* The jump instruction, like call instruction uses relative addressing, but with only an 8-bit signed relative displacement
* x86 instruction set does not provide EIP-relative data access the way it does for control-flow instructions. Thus to do EIP-relative data access, a general-purpose register must first be loaded with EIP
* The one byte NOP instruction is an alias mnemonic for the XCHG EAX, EAX instruction
* There is no way to tell the datatype of something stored in memory by just looking at the location of where it is stored. The datatype is implied by the operations that are used on it. For example, if an instruction loads a value into EAX, comparison is taken place between EAX and 0x10, and JA is used to jump to another location if EAX is greater, then we know that the value is an unsigned int since JA is for unsigned numbers
* EIP can only be changed through CALL, JMP, or RET
* __Floating Point Arithmetic__: Floating point operations are performed using the FPU Register Stack, or the "x87 Stack." FPU is divided into 8 registers, st0 to st7. Typical FPU operations will pop item(s) off the stack, perform on it/them, and push the result back to the stack
  + FLD instruction is for loading values onto the FPU Register Stack
  + FST instruction is for storing values from ST0 into memory 
  + FPU Register Stack can be accessed only by FPU instructions
* __Hard To Remember x86 Instructions With Side Effects__:
  * IMUL reg/mem: register is multiplied with AL, AX, or EAX and the result is stored in AX, DX:AX, or EDX:EAX
  * IDIV reg/mem: takes one parameter (divisor). Depending on the divisor’s size, div will use either AX, DX:AX, or EDX:EAX as the dividend, and the resulting quotient/remainder pair are stored in AL/AH, AX/DX, or EAX/EDX
  * STOS(B/W/D): writes the value AL/AX/EAX to EDI. Commonly used to initialize a buffer to a constant value
  * SCAS(B/W/D): compares AL/AX/EAX with data starting at the memory address EDI
  * LODS(B/W/D): reads 1, 2, or 4 byte value from esi and stores it in al, ax, or eax 
  * REP prefix: repeats an instruction up to ECX times
  * MOVS(B/W/D): moves data with 1, 2, or 4 byte granularity between two addresses. They implicitly use EDI/ESI as the destination/source address, respectively. In addition, they also automatically update the source/destination address depending on the direction flag
  * CLD: clear direction flag. DF: 0
  * STD: set direction flag. DF: 1. If DF is 1, addresses are decremented
  * PUSHAD, POPAD: pushes/pops all 8 general-purpose registers 
  * PUSHFD, POPFD: pushes/pops EFLAGS register 
  * MOVSX: moves a signed value into a register and sign-extends it 
  * MOVZX: moves an unsigned value into a register and zero-extends it
  * CMOVcc: conditional execution on the move operation. If the condition code's (cc) corresponding flag is set in EFLAGS, the mov instruction will be performed. Otherwises, it's just like a NOP instruction 
#
## *<p align='center'> x86-64 (4/24/2017) </p>*
* All addresses and pointers are 64-bit, but virtual addresses must be in canonical form. Modern processors only support 48-bit for address space rather than the full 64-bit that is available. As a result, bit 47 and bits 48-63 must match otherwise an exception will be raised 
* 16 general-purpose registers each 64-bits (RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15)
  + DWORD (32-bit) version can be accessed with a D suffix, WORD (16-bit) with a W suffix, BYTE (8-bit) with a B suffix for registers R8 to R15
  + For registers with alternate names like x86 (e.g. RAX, RCX), size access for register is same as x86. For example, 32-bit version of RAX is EAX and the 16-bit version is DX 
* 16 XMM registers, each 128-bit long. XMM registers are for SIMD instruction set, which is an extension to the x86-86 architecture. SIMD is for performing the same instruction on multiple data at once and/or for floating point operations 
  + Floating point operations were once done using stack-based instruction set that accesses the FPU Register Stack. But now, it can be done using SIMD instruction set 
* Supports instruction pointer-relative addressing. Unlike x86, referencing data will not use absolute address but rather an offset from RIP
* Calling conventions: Parameters are passed to registers. Additional one are stored on stack
  + Windows: first 4 parameters are placed in RCX, RDX, R8, and R9
  + Linux: first 6 parameters are placed in RDI, RSI, RDX, RCX, R8, and R9
* In 32-bit code, stack space can be allocated and unallocated in middle of the function using push or pop. However, in 64-bit code, functions cannot allocate any space in the middle of the function
* Nonleaf functions are sometimes called frame functions because they require a stack frame. All nonleaf functions are required to allocate 0x20 bytes of stack space when they call a function. This allows the function being called to save the register parameters (RCX, RDX, R8, and R9) in that space. If a function has any local stack variables, it will allocate space for them in addition to the 0x20 bytes
* Structured exception handling in x64 does not use the stack. In 32-bit code, the fs:[0] is used as a pointer to the current exception handler frame, which is stored on the stack so that each function can define its own exception handler
* Easier in 64-bit code to differentiate between pointers and data values. The most common size for storing integers is 32 bits and pointers are always 64 bits
* RBP is treated like another GPR. As a result, local variables are referenced through RSP
#
## *<p align='center'> ARM (4/14/2017) </p>*
* ARMv7 uses 3 profiles (Application, Real-time, Microcontroller) and model name (Cortex). For example, ARMv7 Cortex-M is meant for microcontroller and support Thumb-2 execution only 
* Thumb-1 is used in ARMv6 and earlier. Its instructions are always 2 bytes in size
* Thumb-2 is used in ARMv7. Its instructions can be either 2 bytes or 4 bytes in size. 4 bytes Thumb instruction has a .W suffix, otherwise it generates a 2 byte Thumb instruction
* Native ARM instructions are always 4 bytes in size
* Privileges separation are defined by 8 modes. In comparison to x86, User (USR) mode is like ring3 and Supervisor (SVC) mode is like ring0
* Control register is the current program status register (CPSR), also known as application program status register (APSR), which is basically an extended EFLAGS register in x86
* There are 16 32-bit general-purpose registers (R0 - R15), but only the first 12 registers are for general purpose usage
  + R0 holds the return value from function call
  + R13 is the stack pointer (SP)
  + R14 is the link register (LR), which holds return address for function call
  + R15 is the program counter (PC)
* Only load/store instructions can access memory. All other instructions operate on registers 
  + load/store instructions: LDR/STR, LDM/STM, and PUSH/POP
* There are 3 forms of LDR/STR instructions 
  + LDR/STR Ra, [Rb, imm]
  + LDR/STR Ra, [Rb, Rc]
  + LDR/STR Ra, [Rb, Rc, barrel-shifter]. Barrel shifter is performed on Rc, the immediate 
  + extra (pseudo-form): LDR Ra, ="address". This is not valid syntax, but is used by disassembler to make disassembly easier to read. Internally, what's actually executed is LDR Ra, [PC + imm]
* There are 3 addressing modes for LDR/STR: offset, pre-indexed, post-indexed 
  + Offset: base register is never modified 
  + Pre-indexed: base register is updated with the memory address used in the reference operation 
  + Post-indexed: base register is used as the address to reference from and then updated with the offset 
* LDM/STM loads/stores multiple words (32-bits), starting from a base address. Form: LDM/STM<-mode-> Rb[!], {register(s)}
* LDM/STM can use several types of stack: 
  + Descending or ascending: descending means that the stack grows downward, from higher address to lower address. Ascending means that the stack grows upward 
  + Full or empty: full means that the stack pointer points to the last item in the stack. Empty means that the stack pointer points to the next free space
  + Full descending: STMFD (STMDB), LDMFD (LDMIA)
  + Full ascending: STMFA (STMIB), LDMFA (LDMDA)
  + Empty descending: STMED (STMDA), LDMED (LDMIB)
  + Empty ascending: STMEA (STMIA), LDMEA (LDMDB)
* PUSH/POP's form: PUSH/POP {register(s)}
* PUSH/POP and STMFD/LDMFD are functionally the same, but PUSH/POP is used as prologue and epilogue in Thumb state while STMFD/LDMFD is used as prologue and epilogue in ARM state. 
* Instructions for function invocation: B, BX, BL, and BLX
  + B's syntax: B imm. imm is relative offset from R15, the program counter
  + BX's syntax: BX <-register->. X means that it can switch between ARM and THUMB state. If the LSB of the destination is 1, it will execute in Thumb state. BX LR is commonly used to return from function 
  + BL's syntax: BL imm. It stores return address, the next instruction, in LR before transferring control to destination
  + BLX's syntax: BLX imm./<-register->. When BLX uses an offset, it always swap state
* Since instructions can only be 2 or 4 bytes in size, it's not possible to directly use a 32-bit constant as an operand. As a result, barrel shifter can be used to transform the immediate into a larger value 
* For arithmetic operations, the "S" suffix indicates that conditional flags should be set. Whereas, comparison instructions (CBZ, CMP, TST, CMN, and TEQ) automatically update the flags
* Instructions can be conditionally executed by adding conditional suffixes. That is how conditional branch instruction is implemented
* Thumb instruction cannot be conditionally executed, with the exception of B instruction, without the IT instruction. 
  + IT (If-then)'s syntax: ITxyz cc. cc is the conditional suffix for the 1st instruction after IT. xyz are for the 2nd, 3rd, and 4th instructions after IT. It can be either T or E. T means that the condition must match cc for it to be executed. E means that condition must be the opposite of cc for it to be executed
---

# .languages

## *<p align='center'> C++ Reversing (12/13/16) </p>*
* C++ calling convention for this pointer is called thiscall: 
  + On Microsoft Visual C++ compiled binary, this is stored in ecx. Sometimes esi 
  + On g++ compiled binary, this is passed in as the first parameter of the member function as an address 
  + Class member functions are called with the usual function parameters in the stack and with ecx pointing to the class’s object 
* Child classes inherit functions and data from parent classes
* Class’s object in assembly only contains the vfptr (pointer to virtual functions table) and variables. Member functions are not part of it
  + Child class automatically has all virtual functions and data from parent class
  + Even if the programmer did not explicit write the constructor for the class. If the class contains virtual functions, a call to the constructor will be made to fill in the vfptr to point to vtable. If the class inherit from another class, within the constructor there will have a call to the constructor of the parent class  
  + vtable of a class is only referenced directly within the class constructor and destructor
  + Compiler places a pointer immediately prior to the class vtable. It points to a structure that contains information on the name of class that owns the vtable
* Memory spaces for global objects are allocated at compile-time and placed in data or bss section of binary 
* Use Name Mangling to support Method Overloading (multiple functions with same name but accept different parameters). Since in PE or ELF format, a function is only labeled with its name 
---

# .file-formats

## *<p align='center'> ELF Files (1/20/17) </p>*

<p align='center'> <img src="https://upload.wikimedia.org/wikipedia/commons/7/77/Elf-layout--en.svg" height="400"> </p>
<!-- this image is from wikipedia -->

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
* If you compile with the -g option, the compiled binary will contain extra sections with names that start with .debug_. The most important one of the .debug section is .debug_info. It tells you the path of the source file, path of the compilation directory, version of C used, and the line numbers where variables are declared in source code. It will also maintain the parameter names for local functions
* If you compile with the -s option, the compiled binary will not contain symbol table and relocation information. This means that the .symtab will be stripped away, which contains references to variable and local function names. The dynsym section, containing references to unresolved dynamically linked functions, remains because it is needed for program execution
* The -O3 option is the second highest optimization level. The optimizations that it applied will actually result in more bytes than compiled version of the unoptimized binary
* The -funroll-loops option unroll the looping structure of any loops, making it harder for reverse engineer to analyze the compiled binary
* dlsym and dlopen can be used to dynamically resolved function names. This way those library functions won't show up on the Import Table
* __Stripped Binary__: there are 2 sections that contain symbols: .dynsym and .symtab. .dynsym contains dynamic/global symbols, those symbols are resolved at runtime. .symtab contains all the symbols
  * nm command to list all symbols in the binary from .symtab
  * Stripped binary == no .symtab symbol table
  * .dynsym symbol table cannot be stripped since it is needed for runtime, so imported library symbols remain in a stripped binary. But if a binary is compiled statically, it will have no symbol table at all if stripped
  * With non-stripped, gdb can identify local function names and knows the bounds of all functions so we can do: disas "function name"
  * With stripped binary, gdb can’t even identify main. Can identify entry point using the command: info file. Also, can’t do disas since gdb does not know the bounds of the functions so it does not know which address range should be disassembled. Solution: use examine(x) command on address pointed by pc register like: x/14i $pc
* Tools to analyze it: 
  + display section headers: readelf -S
  + display program headers and section to segment mapping: readelf -l
  + display symbol tables: readelf --syms or objdump -t
  + display a section's content: objdump -s -j <-section name-> <-binary file->
  + trace library call: ltrace -f
  + trace sys call: strace -f
  + decompile: retargetable decompiler
---

# .operating-system-concepts

## *<p align='center'> Windows OS (4/1/2017) </p>*
* Windows debug symbol information isn't stored inside the executable like Linux's ELF executable, where debug symbol information has its own section in the executable. Instead, it is stored in the program database (PDB) file
  + To load the PDB File along with the executable (assuming they are in the same directory): File -> Load File -> PDB File
* __Device Driver__: allows third-party developers to run code in the Windows kernel. Located in the kernel. Device drivers create/destroy device objects. User space application interacts with the driver by sending requests to a device object
* __SEH (Structured Exception Handler)__: 32-bit Windows' mechanism for handling exceptions
  * SEH chain is a list of exception handlers within a thread 
  * Each handler can choose to handle the exception or pass to the next one. If the exception made it to the last handler, it is an unhandled exception
  * FS segment register points to the Thread Environment Block (TEB). The first element of TEB is a pointer to the SEH chain
  * SEH chains is a linked list of data structures called EXCEPTION_REGISTRATION records 
  * struct _EXCEPTION_REGISTRATION {
  DWORD prev;
  DWORD handler;
  };
  * To add our own exception handler:
    + push handler
    + push fs:[0]
    + mov fs:[0], esp
* __Handles__: like pointers in that they refer to an object. It is an abstraction that hides a real memory address from the API user, allowing the system to reorganize physical memory transparently to the program
* __Windows Registry (hierarchical database of information)__: used to store OS and program configuration information. Nearly all Windows configuration information is stored in the registry, including networking, driver, startup, user account, and other information 
  + The registry is divided into five top-level sections called root keys
  + __HKEY_LOCAL_MACHINE(HKLM)__: stores settings that are global to the local machine 
  + __HKEY_CURRENT_USER(HKCU)__: stores settings specific to the current user
* DLL files look almost exactly like EXE files. For example, it also uses PE file format. The only real difference is that DLL has more exports than imports
  + Main DLL function is DllMain. It has no label and is not an export in the DLL but is specified in the PE header as the file's entry point
* Before Windows OS switches between threads, all values in the CPU are saved in a structure called the thread context. The OS then loads the thread context of the new thread into the CPU and executes the new thread
* __Pool Memory__: memory allocated by kernel-mode code
  + __Paged Pool__: memory that can be paged out
  + __Non-Paged Pool__: memory that can never be paged out
* __Memory Descriptor Lists (MDL)__: a data structure that describes the mapping between a process's virtual address to a set of physical pages. Each MDL entry describes one contiguous buffer that can be locked (can't be reused by another process) and mapped to a process's virtual address space 
* __Kernal32dll__: interface that provides APIs to interact with Windows OS
* __Ntdll__: interface to kernel. Lowest userland API
  + Native applications are applications that issue calls directly to the Natice API(Ntdll)
* __Windows API's Invocation Pipeline__: User Code -> Kernel32 with functions that end with A (e.g. CreateFileA) -> Kernel32 with functions that end with W (e.g. CreateFileW) -> Ntdll -> Kernel
  + There are two versions of Kernel32 API calls if the call takes in a string: One that ends in A and one that ends in W. A for ASCII and W for wide string
  + In Kernel32 one has the option to call the API with ASCII or wide string. But if one calls it with ASCII, Windows will internally convert it to wide string and call the wide string version of the API
  + Windows API uses stdcall for its calling convention
* List of available system calls is stored in KiServiceTable (which can be found inside the KeServiceDescriptorTable structure) and every system call has an unique number that indexes into it
* System calls can be implemented using software interrupts, such as SYSENTER on x86 or SYSCALL on x86-64
  + On pre-Pentinum 2 processors, APIs call will eventually trigger int 0x2e, where index 0x2e in the IDT is the system call dispatcher
  + SYSCALL invokes system call dispatcher (KiSystemCall64) by loading RIP from IA32_LSTAR MSR (Model Specific Register) 
  + SYSENTER invokes system call dispatcher (KiFastCallEntry) by loading EIP from MSR 0x176
  + System call dispatcher will use the value in EAX to index KiServiceTable for the system call, dispatch the system call, and return to user code
#
## *<p align='center'> Interrupts (4/13/2017) </p>*
* Hardware interrupts are generated by hardware devices/peripherals (asynchronous: can happen at any time)
* Software interrupts (exceptions) are generated by the executing code and can be categorized as either faults or traps (synchronous)
  + fault is a correctable exception such as page fault. After the exception is handled, execution returns to the instruction that causes the fault
  + trap is an exception caused by executing special instruction, such as int 0x80. After the trap is handled, execution returns to the instruction after the the trap
    * int 0x80 is used to make system call. Parameters are passed through GPRs 
      + syscall number: eax 
      + 1st parameter: ebx 
      + 2nd parameter: ecx
      + 3rd parameter: edx
      + 4th parameter: esi 
      + 5th parameter: edi 
      + 6th parameter: ebp 
      + int 0x80 is an old way to make syscall on x86. A more modern implementation is the SYSENTER instruction
* When an interrupt or exception occurs, the processor uses the interrupt number as index into the Interrupt Descriptor Table (IDT), where each entry is a 8 byte KIDTENTRY structure. Each KIDTENTRY structure contains the address of a specific interrupt handler. Base of IDT is stored in the IDT register, which can be accessed through the SIDT instruction
* Interrupt is the communication between CPU and the kernel. The kernel can also notify the running process that an interrupt event has been fired by sending a signal to the process
  + For example, when a breakpoint is hit (INT3), the process will receive the SIGTRAP signal. The signal can then be handled in user code by user-defined signal handler 
* __Interrupt Requests Level (IRQL)__: an interrupt is associated with an IRQL, which indicates its priority
  + IRQL is per-processor. The local interrupt controller (LAPIC) in the processor controls task priority register (TPR) and read-only processor priority register (PPR). Code running in certain PPR level will only fire interrupts that have priority higher than PPR
---

# .anti-reversing

## *<p align='center'> Anti-Disassembly (11/17/16) </p>*
* __Disassembly Technique__: 
  * __Linear Disassembly__: disassembling one instruction at a time linearly. Problem: code section of nearly all binaries will also contain data that isn’t instructions 
  * __Flow-Oriented Disassembly__: for conditional branch, it will process false branch first and note to disassemble true branch later. For unconditional branch, it will add destination to the end of list of places to disassemble in future and then disassemble from that list. For call instruction, most will disassemble the bytes after the call first and then the called location. If there is conflict between the true and false branch when disassembling, disassembler will trust the one it disassembles first
* __Obfuscation Techniques__: Program transformation techniques that output a program that is semantically equivalent to the original program but is more difficult to analyze  
  * __Functions In/Out-Lining__: Performs operations that create inline and outline functions randomly and through multiple passes to obfuscate the call graph  
    * __Inline Functions__: A function that is merged into the body of its caller 
    * __Outline Functions__: Inverse of Inline function where a subportion of a function is extracted to create another function. The subportion of this function is then replaced with a CALL instruction that calls the new function 
  * __Disassembly Desynchronization__: to cause disassembly tools to produce an incorrect program listing. Works by taking advantage of the assumptions/limitations of disassemblers. For every assumption it makes (e.g. process false branch first), there is a corresponding anti-disassembly technique. Desynchronization has the greatest impact on the disassembly, but it is easily defeated by reformatting the disassembly to reflect the correct instruction flow
    * __Opaque Predicates__: conditional construct that looks like conditional code but actually always evaluates to either true or false 
      + __Jump Instructions With The Same Target__: JZ follows by JNZ. Essentially an unconditional jump. The bytes following JNZ instruction could be data but will be disassembled as code
      + __Jump Instructions With A Constant Condition__: XOR follows by JZ. It will always jump so bytes following false branch could be data
    + __Impossible Disassembly__: A byte is part of multiple instructions. Disassembler cannot represent a byte as part of two instructions. Either can the processor, but it doesn't have to because it just needs to execute the instructions 
  * __Opcode Obfuscation__: a more effective technique for preventing correct disassembly by encoding or encrypting the actual instructions
    + Encoding portions of a program can hinder static analysis because disassembly is not possible and hinder debugging because placing breakpoints is difficult. For example, even if the start of an instructions is known, breakpoint cannot be placed until the instruction have been decoded
    + __Virtual Obfuscation__: parts of the program are compiled to the bytecode that corresponds to the instruction set of an undocumented interpreter (usually one that the obfuscator wrote him or herself). The interpreter will be a part of the protected program such that during runtime, the interpreter will translate those bytecode into machine code that corresponds to the original architecture (e.g. x86)  
  * __Destruction of Sequential and Temporal Locality__: Code within a basic block will be right next to each other __(sequential locality)__ and basic blocks relating to each other will be placed in close proximity to maximize instruction cache locality __(temporal locality)__. To obstruct this property and make disassembly harder to understand, a basic block can be further divided and randomized using unconditional jumps 
  * __Function Pointer Problem__: If a function is called indirectly through pointers, IDA xref will only record the first usage
  * __Return Pointer Abuse__: RET is used to jump to function instead of returning from function. Disassembler won’t show any code cross-reference to the target being jumped to. Also, disassembler will prematurely terminate the function since RET is supposed to be used for returning from function
  * __Thwarting Stack-Frame Analysis__: Technique to mess with IDA when deducing numbers of parameters and local variables. For example, the code makes a conditional jump that's always false but in true branch add absurd amount to esp. If the disassembler choose to believe the true branch, the numbers of local variables will be incorrect
  * __Dynamically Computed Target Addresses__: An address to which execution will go to is computed at runtime. This will hinder static analysis
  * __Dead Code Insertion__: Inserts useless code that doesn't affect a program's functionalities
  * __Junk Code Insertion__: Inserts code that never get executed 
  * __Constant Unfolding__: Replaces constant with unnecessary computations that will output the same constant
  * __Arithmetic Substitution via Identities__: Replaces a mathematical statement with one that is more complicated but semantically the same
  * __Pattern-Based Obfuscation__: Transform a sequence of instructions into another sequence of instructions that is more complicated but semantically the same 
  * __Control-Flow Graph Flattening__: Obfuscates control flow by replacing a group of control structures with a dispatcher. Each basic block updates the dispatcher's context so it knows which basic block to execute next
  * __Imported Function Obfuscation (makes it difficult to determine which shared libraries or library functions are used)__: have the program’s import table be initialized by the program itself. The program itself loads any additional libraries it depends on, and once the libraries are loaded, the program locates any required functions within those libraries
    + (Windows) use LoadLibrary function to load required libraries by name and then perform function address lookups within each library using GetProcAddress
    + (Linux) use dlopen function to load the dynamic shared object and use dlsym function to find the address of a specific function within the shared object 
* __Parser Differential Attack__: Makes modifications to the ELF file such that it will still execute fine, but if you try to load it into a disassembler/debugger, the disassembler/debugger will not work properly
  * __Tampering/Removing Section Headers (Linux)__: Makes tools such as gdb and objdump useless since they rely on the section headers to locate information regarding the various sections. Segments are necessary for program execution, not sections. Section headers table is for linking and debugging
    + "The biggest fuck up that (most) analysis tools are doing is that they are using the section headers table of the ELF file to get information about the binary...[because] sections contain more detailed information" - Andre Pawlowski
    + Modifying section headers' flag fields will make disassembler like IDA Pro to display incorrect disassembly listings. For example, changing .text section's flag from AX to WA, even though it still maps to the LOAD segment with flags RE, will trick IDA into not disassembling main along with other local functions. It's because the section headers table tells IDA that the area those functions reside in is not executable
    + In addition to changing the section headers' flags, if we include fake .init section we can trick IDA into not disassembling any of the code starting from the entry point. This can happen since IDA will try to disassemble the .init section before the entry point. But if the .init section overlaps with the entry point, then entry point will not get disassembled at all, especially when the entry point is not marked as executable in the section headers (by messing with the section flag)
    + The entry point provided in the ELF Header is in virtual address. To find the actual offset, find the section that the entry point's virtual address fall under. Once you identified the section, use the section header to figure out entry point's offset: (e_entry - sh_addr) + sh_offset. So if you alter sh_addr (virtual address) field of the section that contains the entry point, disassembler that relys too much on the section headers table (e.g. IDA) won't be able to find the correct entry point in the file. This technique won't work on Radare2 since it prefers information in program headers even if the section headers exist 
    + __Mixing Symbols__: Appends a fake dynamic string table to the end of the binary and overwrite offset of .dynstr entry in section headers table with offset of the fake dynamic string table. This will make imported functions display the fake symbol names
    + If you remove the section headers table, disassembler/debugger will have to rely on program headers even though program headers give us less information. For example, .text, .rodata, and dynsym all belong to the same segment. And without section headers table, we won't be able to differentiate between the sections within a segment. But fully relying on program headers can also lead to failure. For example, another technique to make IDA fail to load an ELF file is to find a program header that is not required for loading and change the offset field to point to a location that is outside the binary
  * __ELF Header Modification__: inserting false information into ELF Header to discourage analysis
    + Simply zero-ing out information regarding section headers table in the ELF Header (e_shoff, e_shentsize, e_shnum, e_shstrndx) can make tools such as readelf and Radare2 unable to display sections even though Section Headers Table still exists within the binary
    + The 6th byte of the ELF Header is EI_DATA, residing within e_ident array, which makes up the first 16 bytes of the ELF Header. EI_DATA specifies the data encoding of the processor-specific data in the file (unknown, little-endian, big-endian). Modifying EI_DATA after compilation will not affect program execution, but will make tools such as readelf, gdb, and radare2 to not work properly since they use this value to interpret the binary
#
## *<p align='center'> Anti-Debugging (11/17/16) </p>*
* __Ptrace (Linux)__: ptrace cannot be called in succession more than once for a process. All debuggers and program tracers use ptrace call to setup debugging for a process, but the process will terminate prematurely if the code itself also contains the call to ptrace 
  + This method can be bypassed by using LD_PRELOAD, which is an environment variable that is set to the path of a shared object. That shared object will be loaded first. As a result, if that shared object contains your own implementation of ptrace, then your own implementation of ptrace will be called instead when the call to ptrace is encountered 
* __Self-Debugging (Windows)__: Windows' version of ptrace. Main process spawns a child process that debugs the process that created it. This prevents debugger from attaching to the same process. It can be bypassed by setting the EPROCESS->DebugPort (the EPROCESS structure is a struct returned by the kernel mode function PsGetProcessId) field to 0
* Windows API provides several functions that can be used by a program to determine if it is being debugged (e.g. isDebuggerPresent)
* Several flags within the PEB structure on Windows provide information about the presence of a debugger
  * Location of PEB can be referenced by the location fs:[30h]. The second item on the PEB struct is BYTE BeingDebugged. The API function, isDebuggerPresent, checks this field to determine if a debugger is present or not
  * __Flags and ForceFlags__: within Reserved4 array in PEB, is ProcessHeap, which is set to location of process’s first heap allocated by loader. This first heap contains a header with fields that tell kernel whether the heap was created within a debugger. The fields are Flags and ForceFlags. If the Flags field does not have the HEAP_GROWABLE(0x2) flag set, then the process is being debugged. Also, if ForceFlags != 0, then the process is being debugged. The location of both Flags and ForceFlags in the heap depends on whether the machine is 32-bit or 64-bit and also the version of Window Operating System (e.g. Windows XP, Windows Vista)
  * __NTGlobalFlag__: Since processes run slightly differently when started by a debugger, they create memory heaps differently. The information that the system uses to determine how to create heap structures is stored in the NTGlobalFlag field in the PEB at offset 0x68 in x86 and 0xbc in x64. If value at this location is 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK(0x10) | FLG_HEAP_ENABLE_FREE_CHECK(0x20) | FLG_HEAP_VALIDATE_PARAMETERS(0x40)), we know that we are running in debugger
* __INT Scanning__: Search the .text section for the 0xCC byte. If it exists, that means that a software breakpoint has been set and the process is under a debugger 
* __Code Checksums__:  Instead of scanning for 0xCC, this check simply performs a cyclic redundancy check (CRC) or a MD5 checksum of the opcodes. This not only catches software breakpoints, but also code patches 
* __Anti-Step-Over__: the rep or movs(b|w|d) instruction can be used to overwrite/remove software breakpoints that are set after it
* __Hardware Breakpoints (Windows)__: Get a handle to current thread using GetCurrentThread(). Get registers of current thread using GetThreadContext(). Check if registers DR0-DR3 is set, if it is then there are hardware breakpoints set. On Linux, user code can't access hardware breakpoints so it's not possible to check for it  
* __Interrupts__: Manually adding/setting interrupts to the code to help detect present of a debugger
  + __False Breakpoints and SIGTRAP Handler__: a breakpoint is created by overwriting the first byte of instruction with an int3 opcode (0xcc). To setup a false breakpoint then we simply insert int3 into the code. This raises a SIGTRAP when int3 is executed. If our code has a signal handler for SIGTRAP, the handler will be executed before resuming to the instruction after int3. But if the code is under the debugger, the debugger will catch the SIGTRAP signal instead and might not pass the signal back to the program, resulting in the signal handler not being executed 
  + __Two Byte Interrupt 3__: instead of 0xCC, it's 0xCD 0x03. Can also be used as false breakpoint
  + __Interrupt 0x2C__: raises a debug assertion exception. This exception is consumed by WinDbg 
  + __Interrupt 0x2D__: issues an EXCEPTION_BREAKPOINT (0x80000003) exception if no debugger is attached. Also it might also led to a single-byte instruction being skipped depending on whether the debugger chooses the EIP register value or the exception address as the address from which to resume 
  + __Interrupt 0x41__: this interrupt cannot be executed succressfully in ring 3 because it has a DPL of zero. Executing this interrupt will result in an EXCEPTION_ACCESS_VIOLATION (0Xc0000005) exception. Some debugger will adjust its DPL to 3 so that the interrupt can be executed successfully in ring 3. This results in the exception handler to not be executed
  + __ICEBP (0xF1)__: generates a single step exception
  + __Trap Flag Check__: Trap Flag is part of the EFLAGS register. IF TF is 1, CPU will generate Single Step exception(int 0x01h) after executing an instruction. Trap Flag can be manually set to cause next instruction to raise an exception. If the process is running under a debugger, the debugger will not pass the exception to the program so the exception handler will never be ran
  + __MOV SS__: when you write to SS (e.g. pop ss), CPU will lock all interrupts until the end of the next instruction. Therefore, if you are single-stepping through it with a debugger, the debugger will not stop on the next instruction but the instruction after the next one. One way to detect debugger is for the next instruction after a write to SS to be pushfd. Since the debugger did not stop there, it will not clear the trap flag and pushfd will push the value of trap flag (plus rest of EFLAGS) onto the stack
  + __Instruction Counting__: register an exception handler. Use an int 3 instruction to trigger it and set hardware breakpoints. When a hardware breakpoint is reached, the same exception handler will be triggered due to EXCEPTION_SINGLE_STEP and a count of how many times it is triggered by EXCEPTION_SINGLE_STEP is kept. Debugger will mess with the instruction counts by not calling the previously set exception handler when a hardware breakpoint is reached. Checking the value of the instruction counts will tell us if the program is running under a debugger or not
* __Timing Checks__:  record a timestamp, perform some operations, take another timestamp, and then compare the two timestamps. If there is a lag, you can assume the presence of a debugger
* __rdtsc Instruction (0x0F31)__: this instruction returns the count of the number of ticks since the last system reboot as a 64-bit value placed into EDX:EAX. Simply execute this instruction twice and compare the difference between the two readings
* __TLS Callbacks__: (Windows only) Most debuggers start at the program’s entry point as defined by the PE header. TlsCallback is traditionally used to initialze thread-specific data before a thread runs, so TlsCallback is called before the entry point and therefore can execute secretly in a debugger. To make it harder to find anti-debugging checks, anti-debugging checks can be placed in TlsCallback
* __/proc/self/status File (Linux)__: a dynamic file that exists for every process. It includes information on whether a process is being traced
#
## *<p align='center'> Anti-Emulation (2/5/2017) </p>*
* Using emulation allows reverse engineer to bypass many anti-debugging techniques
* __Detection through Syscall__: invoke various uncommon syscalls and check if it contains expected value. Since there are OS features not properly implemented, it means that the process is running under emulation
* __CPU Inconsistencies Detection__: try executing privileged instructions in user mode. If it succeeded, then it is under emulation
  + WRMSR is a privileged instruction (Ring 0) that is used to write values to a MSR register. Values in MSR registers are very important. For example, the SYSCALL instruction invokes the system-call handler by loading RIP from IA32_LSTAR MSR. As a result, WRMSR instruction cannot be executed in user-mode  
* __Timing Delays__: execution under emulation will be slower than running under real CPU
---

# .encodings

## *<p align='center'> String Encoding (12/12/16) </p>*
* There are only 128 characters defined in ASCII and 95 of them are human-readable
* ASCII only used 7 bits, but the extra bit is still not enough to encode all the other languages
* Various encoding schemes were invented but none covered every languages until Unicode came along
* Unicode is a large table mapping characters to numbers (or a table of code points for characters) and the different UTF encodings specify how these numbers are encoded as bits
* Characters are referred to by their “Unicode code point”
* The primary cause of garbled text is: Somebody is trying to read a byte sequence using the wrong encoding
* All characters available in the ASCII encoding only take up a single byte in UTF-8 and they're the exact same bytes as are used in ASCII. In other words, ASCII maps 1:1 unto UTF-8. Any character not in ASCII takes up two or more bytes in UTF-8
#
## *<p align='center'> Data Encoding (12/15/16) </p>*
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
* Data encoding example: Base64
  * Represents binary data in ASCII string format
  * Converts binary data into character set of 64 characters
  * Most common character set is MIME’s Base64, which uses A-Z, a-z, and 0-9 for the first 62 values and + / for the last two
  * Bits are read in blocks of six. The number represented by the 6 bits is used as an index into a 64-byte long string
  * One padding character may be presented at the end of the encoded string (typically =). If padded, length of encoded string will be divisible by 4
  * Easy to develop a custom substitution cipher since the only item that needs to be changed is the indexing string

[Go to Table of Contents](#table-of-contents)
