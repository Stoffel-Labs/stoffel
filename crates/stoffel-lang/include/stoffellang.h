#ifndef STOFFELLANG_H
#define STOFFELLANG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compiler Options
typedef struct {
    int optimize;
    uint8_t optimization_level;
    int print_ir;
} CCompilerOptions;

// Error Handling
typedef struct {
    char* message;
    char* file;
    size_t line;
    size_t column;
    int severity;  // 0=Warning, 1=Error, 2=Fatal
    int category;  // 0=Syntax, 1=Type, 2=Semantic, 3=Internal
    char* code;
    char* hint;    // nullable
} CCompilerError;

typedef struct {
    CCompilerError* errors;
    size_t count;
} CCompilerErrors;

// Constants
typedef union {
    int64_t i64_val;
    int32_t i32_val;
    int16_t i16_val;
    int8_t i8_val;
    uint64_t u64_val;
    uint32_t u32_val;
    uint16_t u16_val;
    uint8_t u8_val;
    int64_t float_val;  // Fixed-point representation
    int bool_val;
    char* string_val;
    size_t object_val;
    size_t array_val;
    size_t foreign_val;
} CConstantData;

typedef struct {
    int const_type;  // 0=I64, 1=I32, 2=I16, 3=I8, 4=U8, 5=U16, 6=U32, 7=U64, 8=Float, 9=Bool, 10=String, 11=Object, 12=Array, 13=Foreign, 14=Closure, 15=Unit, 16=Share
    CConstantData data;
} CConstant;

// Instructions
typedef struct {
    uint8_t opcode;
    size_t operand1;
    size_t operand2;
    size_t operand3;
} CInstruction;

// Bytecode Chunk
typedef struct {
    CInstruction* instructions;
    size_t instruction_count;
    CConstant* constants;
    size_t constant_count;
} CBytecodeChunk;

// Function Chunk
typedef struct {
    char* name;
    CBytecodeChunk chunk;
} CFunctionChunk;

// Compiled Program
typedef struct {
    CBytecodeChunk main_chunk;
    CFunctionChunk* function_chunks;
    size_t function_count;
} CCompiledProgram;

// Compilation Result
typedef struct {
    int success;  // 1 for success, 0 for failure
    CCompiledProgram* program;  // nullable, only set on success
    CCompilerErrors errors;     // contains errors/warnings
} CCompilationResult;

// Main API Functions

/**
 * Compile Stoffel source code to bytecode
 *
 * @param source The source code string (null-terminated)
 * @param filename The filename for error reporting (null-terminated)
 * @param options Compiler options (nullable, uses defaults if NULL)
 * @return Compilation result containing either compiled program or errors
 *         Must be freed with stoffel_free_compilation_result()
 */
CCompilationResult* stoffel_compile(const char* source, const char* filename, const CCompilerOptions* options);

/**
 * Get the compiler version string
 *
 * @return Version string (do not free, points to static data)
 */
const char* stoffel_get_version(void);

// Memory Management Functions

/**
 * Free a compilation result and all associated memory
 *
 * @param result The result to free
 */
void stoffel_free_compilation_result(CCompilationResult* result);

/**
 * Free a compiled program and all associated memory
 *
 * @param program The program to free
 */
void stoffel_free_compiled_program(CCompiledProgram* program);

/**
 * Free a bytecode chunk and all associated memory
 *
 * @param chunk The chunk to free
 */
void stoffel_free_bytecode_chunk(const CBytecodeChunk* chunk);

/**
 * Free compiler errors and all associated memory
 *
 * @param errors The errors to free
 */
void stoffel_free_compiler_errors(const CCompilerErrors* errors);

// Instruction Opcodes
#define STOFFEL_OP_LD      0   // Load from stack
#define STOFFEL_OP_LDI     1   // Load immediate
#define STOFFEL_OP_MOV     2   // Move register to register
#define STOFFEL_OP_ADD     3   // Add
#define STOFFEL_OP_SUB     4   // Subtract
#define STOFFEL_OP_MUL     5   // Multiply
#define STOFFEL_OP_DIV     6   // Divide
#define STOFFEL_OP_MOD     7   // Modulo
#define STOFFEL_OP_AND     8   // Bitwise AND
#define STOFFEL_OP_OR      9   // Bitwise OR
#define STOFFEL_OP_XOR     10  // Bitwise XOR
#define STOFFEL_OP_NOT     11  // Bitwise NOT
#define STOFFEL_OP_SHL     12  // Shift left
#define STOFFEL_OP_SHR     13  // Shift right
#define STOFFEL_OP_JMP     14  // Unconditional jump
#define STOFFEL_OP_JMPEQ   15  // Jump if equal
#define STOFFEL_OP_JMPNEQ  16  // Jump if not equal
#define STOFFEL_OP_JMPLT   17  // Jump if less than
#define STOFFEL_OP_JMPGT   18  // Jump if greater than
#define STOFFEL_OP_CALL    19  // Function call
#define STOFFEL_OP_RET     20  // Return
#define STOFFEL_OP_PUSHARG 21  // Push argument
#define STOFFEL_OP_CMP     22  // Compare

// Error Severity Levels
#define STOFFEL_SEVERITY_WARNING 0
#define STOFFEL_SEVERITY_ERROR   1
#define STOFFEL_SEVERITY_FATAL    2

// Error Categories
#define STOFFEL_CATEGORY_SYNTAX    0
#define STOFFEL_CATEGORY_TYPE      1
#define STOFFEL_CATEGORY_SEMANTIC  2
#define STOFFEL_CATEGORY_INTERNAL  3

// Constant Types
#define STOFFEL_CONST_I64     0
#define STOFFEL_CONST_I32     1
#define STOFFEL_CONST_I16     2
#define STOFFEL_CONST_I8      3
#define STOFFEL_CONST_U8      4
#define STOFFEL_CONST_U16     5
#define STOFFEL_CONST_U32     6
#define STOFFEL_CONST_U64     7
#define STOFFEL_CONST_FLOAT   8
#define STOFFEL_CONST_BOOL    9
#define STOFFEL_CONST_STRING  10
#define STOFFEL_CONST_OBJECT  11
#define STOFFEL_CONST_ARRAY   12
#define STOFFEL_CONST_FOREIGN 13
#define STOFFEL_CONST_CLOSURE 14
#define STOFFEL_CONST_UNIT    15
#define STOFFEL_CONST_SHARE   16

#ifdef __cplusplus
}
#endif

#endif // STOFFELLANG_H