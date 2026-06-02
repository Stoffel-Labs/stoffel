# Stoffel-Lang Compiler

A compiler for the Stoffel programming language, with support for generating bytecode compatible with the StoffelVM.

## Features

- Modern syntax inspired by Rust, Python, and JavaScript
- Strong static typing with type inference
- Register-based bytecode generation
- VM-compatible binary output
- Optimizations for efficient code execution

## Installation

### Prerequisites

- Rust and Cargo (latest stable version)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/Stoffel-Lang.git
cd Stoffel-Lang

# Build the project
cargo build --release

# The compiler binary will be available at target/release/stoffellang
```

## Usage

### Basic Compilation

```bash
# Compile a source file
./stoffellang path/to/source.stfl

# Enable optimizations
./stoffellang -o path/to/source.stfl

# Set optimization level (0-3)
./stoffellang -O2 path/to/source.stfl

# Print intermediate representations (tokens, AST)
./stoffellang --print-ir path/to/source.stfl
```

### Generating VM-Compatible Binaries

The compiler can generate binary files that are compatible with the StoffelVM:

```bash
# Generate a VM-compatible binary (outputs to source.stfb by default)
./stoffellang -b path/to/source.stfl

# Specify output file
./stoffellang -b -o output.stfb path/to/source.stfl
```

## Language Examples

### Hello World

```
fn main() {
    println("Hello, world!");
}
```

### Variables and Types

```
fn main() {
    let x: i32 = 42;
    let y = 3.14;  // Type inference
    let name = "Stoffel";
    let is_active = true;
    
    println("x = {}, y = {}", x, y);
}
```

### Functions

```
fn add(a: i32, b: i32) -> i32 {
    return a + b;
}

fn main() {
    let result = add(5, 7);
    println("5 + 7 = {}", result);
}
```

## VM Compatibility

The compiler now supports generating binary files that are compatible with the StoffelVM. This allows Stoffel programs to be executed on any platform that supports the VM.

The binary format includes:
- A rich type system (integers, floats, strings, booleans, arrays, objects)
- Function definitions with metadata
- Optimized bytecode instructions
- Constant pools for efficient value storage

## Learn More

To learn more about what you can build with Stoffel, visit 
[stoffelmpc.com](https://stoffelmpc.com?utm_source=github&utm_medium=readme&utm_campaign=stoffel-lang-repo&utm_term=mpc)
