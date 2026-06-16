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
# Generate a VM-compatible binary (outputs to source.stflb by default)
./stoffellang -b path/to/source.stfl

# Specify output file
./stoffellang -b -o output.stflb path/to/source.stfl
```

## Language Examples

StoffelLang is Pythonic: indentation-based blocks, `def` for functions,
`var` for (mutable) variables, and `#` comments.

### Hello World

```python
def main() -> None:
  print("Hello, world!")
```

### Variables and Types

```python
def main() -> None:
  var x: int32 = 42i32      # sized integers: int8..int64, uint8..uint64
  var y = 3.14              # float (exponents work too: 2.5e-2)
  var f: fix64 = 1.5        # fixed-point (MPC-friendly): fix32 / fix64
  var name = "Stoffel" + "!"
  var is_active = True
  print(name, len(name), x, y, f, is_active)
```

### Functions

```python
# Literal default values and named arguments are supported.
def add(a: int64, b: int64 = 7) -> int64:
  return a + b

def main() -> int64:
  return add(5) + add(b: 2, a: 1)
```

### Control Flow

```python
def main() -> int64:
  var sum = 0
  for i in 0..10:        # ranges are end-EXCLUSIVE
    if i % 2 == 1:
      continue
    if i > 6:
      break
    sum += i
  while sum < 100:
    sum = sum * 2
  return sum
```

### Bitwise Operations

`and`, `or`, `xor` are logical on bools and bitwise on matching integer
types (Nim-style); `shl`/`shr` are the shift operators.

```python
def main() -> int64:
  var mask = 12 and 10   # 8
  var bits = 12 xor 10   # 6
  var shifted = 1 shl 4  # 16
  return mask + bits + shifted
```

### Pythonic Conveniences

```python
enum Color:
  Red
  Green
  Blue          # auto-increment int64 constants; Color.Blue == 2

def total(*xs) -> int64:   # varargs pack into a list
  var sum = 0
  for x in xs:
    sum += x
  return sum

def main() -> int64:
  var xs: list[int64] = [1, 2, 3, 4, 5]
  var mid = xs[1:3]                       # slicing (negative bounds work)
  var last = xs[-1]                       # negative indexing
  var evens = [x for x in xs if x % 2 == 0]  # comprehensions
  assert 2 in xs, "membership with 'in'"  # assert with optional message
  var s = f"sum is {last}"                # f-strings (variable interpolation)
  match last:                             # match on literals; _ is default
    case 5:
      print(s)
    case _:
      pass
  return total(1, 2) + len(evens) + len(mid)
```

### Secret (MPC) Values

```python
def main() -> int64:
  var a: secret int64 = Share.from_clear(10)
  var b: secret int64 = a + 5
  return b.reveal()
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
