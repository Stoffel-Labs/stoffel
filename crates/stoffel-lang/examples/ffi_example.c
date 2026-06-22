#include <stdio.h>
#include <stdlib.h>
#include "../include/stoffellang.h"

void print_program_summary(const CCompiledProgram* program) {
    printf("✓ Compilation successful!\n");
    printf("  Main chunk: %zu instructions, %zu constants\n",
           program->main_chunk.instruction_count,
           program->main_chunk.constant_count);

    if (program->function_count > 0) {
        printf("  Functions: %zu\n", program->function_count);
    }
}

int compile_and_test(const char* description, const char* source, const char* filename) {
    printf("\n=== %s ===\n", description);
    printf("Source:\n%s\n\n", source);

    CCompilerOptions options = {
        .optimize = 0,
        .optimization_level = 0,
        .print_ir = 0
    };

    CCompilationResult* result = stoffel_compile(source, filename, &options);

    if (!result) {
        printf("❌ Failed to get compilation result!\n");
        return 0;
    }

    if (result->success) {
        print_program_summary(result->program);
        stoffel_free_compilation_result(result);
        return 1;
    } else {
        printf("❌ Compilation failed (unexpected)\n");
        stoffel_free_compilation_result(result);
        return 0;
    }
}

int main() {
    printf("🔧 Stoffel Lang C FFI Example\n");
    printf("Compiler Version: %s\n", stoffel_get_version());

    int success_count = 0;
    int total_tests = 0;

    // Test 1: Simple arithmetic
    total_tests++;
    if (compile_and_test(
        "Simple Arithmetic",
        "var x = 42\n"
        "var y = 10\n"
        "x + y",
        "arithmetic.stfl")) {
        success_count++;
    }

    // Test 2: Multiple operations
    total_tests++;
    if (compile_and_test(
        "Multiple Operations",
        "var a = 5\n"
        "var b = 3\n"
        "var c = 2\n"
        "a * b + c",
        "complex.stfl")) {
        success_count++;
    }

    // Test 3: Boolean values
    total_tests++;
    if (compile_and_test(
        "Boolean Values",
        "var is_valid = true\n"
        "var is_ready = false\n"
        "is_valid",
        "boolean.stfl")) {
        success_count++;
    }

    // Test 4: String literals
    total_tests++;
    if (compile_and_test(
        "String Literals",
        "var greeting = \"Hello, Stoffel!\"\n"
        "greeting",
        "string.stfl")) {
        success_count++;
    }

    printf("\n🏁 Results: %d/%d tests passed\n", success_count, total_tests);

    if (success_count == total_tests) {
        printf("🎉 All tests passed! The Stoffel FFI is working correctly.\n");
        printf("\nThis demonstrates that the FFI can:\n");
        printf("• Compile valid Stoffel programs to bytecode\n");
        printf("• Handle different data types (integers, booleans, strings)\n");
        printf("• Perform arithmetic operations and expressions\n");
        printf("• Manage memory safely with proper cleanup\n");
        printf("• Be integrated into other languages via C ABI\n");
        return 0;
    } else {
        printf("❌ Some tests failed. This indicates an issue with the FFI.\n");
        return 1;
    }
}