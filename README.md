# Reverse-Engineering-Journal
I put anything I find interesting regarding reverse engineering in this journal. The date beside each heading denotes the start date that I added the topic, but most of the time I will still be adding bullets to that heading days later. 

#### *12/18/16 (General Knowledge)*
* A hash function is a mathematical process that takes in an arbitrary-sized input and produces a fixed-size result
* First argument to __libc_start_main() is a pointer to main for ELF files
* nm: displays symbols in binary 
* ldd: print shared library dependencies
* To look at instructions starting from pc for stripped binary in gdb: x/14i $pc
* Set hardware breakpoint in GDB: hbreak 
* Set watchpoint in GDB: watch only break on write, rwatch break on read, awatch break on read/write
* Thunk function: simple function that jumps to another function
* ASLR is turned off by default in GDB. To turn it on: set disable-randomization off
* (32 bits Windows exe) FS register points to the beginning of current thread's environment block (TEB). Offset zero in TEB is the head of 
  a linked list of pointers to exception handler functions

#### *12/24/16 ([HARD TO REMEMBER] x86 Instructions With Side Effects)*
* IMUL reg/mem: register is multiplied with AL, AX, or EAX and the result is stored in AX, DX:AX, or EDX:EAX
* IDIV reg/mem: takes one parameter (divisor). Depending on the divisor’s size, div will use either AX, DX:AX, or EDX:EAX as the dividend, and the resulting quotient/remainder pair are stored in AL/AH, AX/DX, or EAX/EDX
* STOS: writes the value AL/AX/EAX to EDI. Commonly used to initialize a buffer to a constant value
* SCAS: compares AL/AX/EAX with data starting at the memory address EDI
* CLD: clear direction flag
* STD: set direction flag
* REP prefix: repeats an instruction up to ECX times
* MOVSB/MOVSW/MOVSD instructions move data with 1, 2, or 4 byte granularity between two addresses. They implicitly use EDI/ESI as the destination/source address, respectively. In addition, they also automatically update the source/destination address depending on the direction flag

#### *11/17/16 (Anti-Disassembly)*
* __Linear disassembly__: disassembling one instruction at a time linearly. Problem: code section of nearly all binaries will also contain data that isn’t instructions 
* __Flow-oriented disassembly__: process false branch first and note to disassemble true branch in future. When it reaches a unconditional jump, it will add the dest to list of places to disassemble in future. It will then step back and disassemble from the list of places it noted previously. For call instruction, most will disassemble the bytes after the call first and then the called location. If there is conflict between the true and false branch when disassembling, disassembler will trust the one it disassembles first
* Use inline functions to obscure function declaration
* __Disassembly Desynchronization__: to cause disassembly analysis tools to produce an incorrect program listing. Works by taking advantage of the assumptions and limitations of disassemblers. Desynchronization had the greatest impact on the disassembly, but it was easily defeated by reformatting the disassembly to reflect the correct instruction flow
  + __Jump instructions with the same target__: jz follows by jnz. Essentially an unconditional jump. The bytes following jnz instruction could be data but will be disassembled as code
  + __Jump instructions with a constant condition__: xor follows by jz. It will always jump so bytes following false branch could be data
  + __Impossible disassembly__: A byte is part of multiple instructions. No disassembler will represent a byte as part of two instructions, but the processor has no such limitation
* __Opcode Obfuscation__: a more effective technique for preventing correct disassembly by encoding or encrypting the actual instructions
  + Encoding portions of a program has the dual effect of hindering static analysis because disassembly is not possible and of hindering debugging because placing breakpoints is difficult. Even if the start of each instructions is known, breakpoints cannot be placed until instructions have been decoded
  + Virtual obfuscation
* __Function pointer problem__: if a function call func using the same ptr multiple times, ida pro xref only record the first usage
* __Return pointer abuse__: ret instruction is used to jump to function instead of returning from function. Disassembler doesn’t show any code cross-reference to the target being jumped to. Also, disassembler will prematurely terminate the function
* __Thwarting stack-frame analysis__: technique to mess ida pro when deducing numbers of param and local variables. Make a conditional jump that always false but in true branch add absurd amount to esp
* __Dynamically Computed Target Addresses__: an address to which execution will flow is computed at runtime. The intent is to hide control flow from static analysis
* More complex control flow hiding: program uses multiple threads or child processes to compute control flow information and receive that information via interprocess communication (for child processes) or synchronization primitives (for multiple threads)
* __Imported Function Obfuscation (makes it difficult to determine which shared lib or lib func are used)__: have the program’s import table to have been properly initialized by the program itself. The program itself loads any additional lib it depends on, and once the lib are loaded, the program locates any required functions within those lib
  + (Windows) use LoadLibrary function to load required lib by name and then perform function address lookups within each lib using the GetProcAddress func
* Tip-offs that a binary is obfuscated:
  + Very little code is highlighted in the navigation band
  + Very few functions are listed in Functions window. Often only the start function
  + Very few imported functions in the Imports window
  + Very few legible strings appear in Strings window
  + One or more program sections will be both writable and executable (Segments Window)
  + Nonstandard section names such as UPXo or .shrink are used

#### *11/17/16 (Anti-Debugging)*
* For Linux Only: This is an elegant technique to detect if a debugger or program tracer such as strace or ltrace is being used on the target program. The premise of this technique is that a ptrace[PTRACE_TRACEME] cannot be called in succession more than once for a process. All debuggers and program tracers use this call to setup debugging for a process
* Self-Debugging (Window’s version of ptrace): main process spawns a child process that debugs the process that created the child process. This can be bypassed be setting the EPROCESS->DebugPort (the EPROCESS structure is a struct returned by the kernel mode function PsGetProcessId) field to 0
* Windows API provides several functions that can be used by a program to determine if it is being debugged (e.g. isDebuggerPresent)
* Several flags within the PEB structure provide information about the presence of a debugger
* Location of PEB can be referenced by the location fs:[30h]. The second item on the PEB struct is BYTE BeingDebugged
* __ProcessHeap Flag__: within Reserved4 array in PEB, is ProcessHeap, which is set to location of process’s first heap allocated by loader. This first heap contains a header with fields that tell kernel whether the heap was created within a debugger, known as ForceFlags fields
* __NTGlobalFlag__: Since processes run slightly differently when started with a debugger, they create memory heaps differently. The information that the system uses to determine how to create heap structures is stored at an undocumented location in the PEB at offset 0x68. If value at this location is 0x70, we know that we are running in debugger
* __INT Scanning__: INT 3 (0xCC) is software interrupt used by debuggers to temporarily replace an instruction in a running program and to call the debug exception handler if the process is being traced (e.g. ptrace)- how debugger make software breakpoint. Have a process scan its own code for an INT 3 modification by searching the code for the oxCC opcode
* __Setting up false breakpoints__: a breakpoint is created by overwriting the address with an int3 opcode (0xcc). To setup a false breakpoint then we simply insert an int3 into the code. This also raises a SIGTRAP, and thus if our code has a signal handler we can continue processing after the breakpoint
* __Code Checksums__:  Instead of scanning for 0xCC, this check simply performs a cyclic redundancy check (CRC) or a MD5 checksum of the opcodes in the malware
* __Timing Checks__:  record a timestamp, perform some operations, take another timestamp, and then compare the two timestamps. If there is a lag, you can assume the presence of a debugger
* __rdtsc Instruction (0x0F31)__: this instruction returns the count of the number of ticks since the last system reboot as a 64-bit value placed into EDX:EAX. Simply execute this instruction twice and compare the difference between the two readings
* __TLS Callbacks__: Most debuggers start at the program’s entry point as defined by the PE header. A TLS callback can be used to execute code before the entry point and therefore execute secretly in a debugger. TLS is a Windows storage class in which a data object is not an automatic stack variable, yet is local to each thread that runs the code. Basically, TLS allows each thread to maintain a different value for a variable declared using TLS. TLS callback functions were designed to initialize and clear TLS data objects
* Clearing hardware breakpoints

#### *12/5/16 (Breakpoints)*
* Software breakpoint: debugger read and store the first byte and then overwrite the first byte with 0xcc (int 3). When CPU hits the breakpoint, SIGTRAP signal is raised, process is stopped, and internal lookup occurs and the byte is flipped back
* Hardware breakpoints are set at CPU level, in special registers called debug registers (DR0 through DR7)
* Only DR0 - DR3 registers are reserved for breakpoint addresses
* Before the CPU attempts to execute an instruction, it first checks to see whether the address is currently enabled for a hardware breakpoint. If the address is stored in debug registers DR0–DR3 and the read, write, or execute conditions are met, an INT1 is fired and the CPU halts
* Can check if someone sets a hardware breakpoint by using GetThreadContext() and checks if DR0-DR3 is set
* When a debugger is setting a memory breakpoint, it is changing the permissions on a region, or page, of memory
* Guard page: Any access to a guard page results in a one-time exception, and then the page returns to its original status. Memory breakpoint changes permission of the page to guard

