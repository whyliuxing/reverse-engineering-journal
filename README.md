# Reverse-Engineering-Journal
I put anything I find interesting regarding reverse engineering in this journal. The date beside each heading denotes the start date that I added the topic, but most of the time I will still be adding bullets to that heading days later. 

#### 12/18/16 (General Knowledge)
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
* debug registers 0 through 7 (DR0 - DR7) are used to control the use of hardware breakpoints. DR0 through DR3 are used to specify breakpoint addresses, while DR6 and DR7 are used to enable and disable specific hardware breakpoints

#### 12/24/16 ([HARD TO REMEMBER] x86 Instructions With Side Effects)
* IMUL reg/mem: register is multiplied with AL, AX, or EAX and the result is stored in AX, DX:AX, or EDX:EAX
* IDIV reg/mem: takes one parameter (divisor). Depending on the divisor’s size, div will use either AX, DX:AX, or EDX:EAX as the dividend, and the resulting quotient/remainder pair are stored in AL/AH, AX/DX, or EAX/EDX
* STOS: writes the value AL/AX/EAX to EDI. Commonly used to initialize a buffer to a constant value
* SCAS: compares AL/AX/EAX with data starting at the memory address EDI
* CLD: clear direction flag
* STD: set direction flag
* REP prefix: repeats an instruction up to ECX times
* MOVSB/MOVSW/MOVSD instructions move data with 1, 2, or 4 byte granularity between two addresses. They implicitly use EDI/ESI as the destination/source address, respectively. In addition, they also automatically update the source/destination address depending on the direction flag

#### 11/17/16 (Anti-Disassembly) 
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

