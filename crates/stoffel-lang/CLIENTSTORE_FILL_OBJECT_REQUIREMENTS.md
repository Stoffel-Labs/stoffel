# ClientStore.fill_object Implementation Requirements

## Goal

Implement a method `ClientStore.fill_object(obj, client_idx)` that automatically fills all secret fields of an object with shares from a specified client.

## Proposed API

```stoffel
# Define an object/struct with secret fields
object UserData:
  public_id: int64
  secret_value: secret int64
  secret_balance: secret int64

def main() -> nil:
  var user: UserData = UserData()

  # Fill all secret fields from client 0
  ClientStore.fill_object(user, 0)
  # Equivalent to:
  # user.secret_value = ClientStore.take_share(0, 0)
  # user.secret_balance = ClientStore.take_share(0, 1)
```

## Implementation Requirements

### 1. **Object/Struct Support** (Prerequisites)

Currently, the codebase has `ObjectDefinition` in the AST but may not be fully implemented. We need:

- **Parser Support**:
  - Parse object/struct definitions with syntax like:
    ```stoffel
    object StructName:
      field1: type1
      secret field2: secret type2
    ```
  - Parse object instantiation: `var obj = StructName()`
  - Parse field access: `obj.field_name`
  - Parse field assignment: `obj.field_name = value`

- **Semantic Analysis**:
  - Track object types in symbol table
  - Validate field access (check field exists in object type)
  - Validate field types during assignment
  - Track which fields are secret (from `is_secret` flag in `FieldDefinition`)

- **Code Generation**:
  - Generate bytecode for object allocation
  - Generate bytecode for field access (load/store)
  - Handle memory layout for objects

### 2. **Type System Enhancements**

Update `SymbolType` in `src/symbol_table.rs`:

```rust
pub enum SymbolType {
    // ... existing types ...
    Object {
        name: String,
        fields: Vec<(String, SymbolType, bool)>, // (name, type, is_secret)
    },
}
```

### 3. **ClientStore.fill_object Implementation**

#### A. Symbol Table Registration (`src/symbol_table.rs`)

Add the builtin function:

```rust
let fill_object_info = SymbolInfo {
    name: "fill_object".to_string(),
    kind: SymbolKind::BuiltinFunction {
        parameters: vec![
            SymbolType::TypeName("ClientStore".to_string()),
            SymbolType::Unknown, // Any object type
            SymbolType::Int64,   // client_idx
        ],
        return_type: SymbolType::Void,
    },
    symbol_type: SymbolType::Void,
    is_secret: false,
    defined_at: SourceLocation::default(),
};
```

#### B. Semantic Analysis (`src/semantic.rs`)

Special validation for `fill_object`:

1. **Argument Type Checking**:
   - First argument: must be `ClientStore`
   - Second argument: must be an object/struct type
   - Third argument: must be `int64` (client index)

2. **Field Discovery**:
   - Look up the object type in the symbol table
   - Extract all fields marked as `is_secret: true`
   - Validate that the object has at least one secret field

3. **Share Index Calculation**:
   - Determine the order of secret fields (e.g., by definition order)
   - Map each secret field to a share index (0, 1, 2, ...)
   - This needs to be deterministic and match VM expectations

4. **Mutability Check**:
   - Ensure the object variable is mutable (declared with `var`, not `let`)
   - Error if trying to fill an immutable object

#### C. Code Generation (`src/codegen.rs`)

Register `fill_object` as a known builtin:

```rust
known_builtins.insert("fill_object".to_string());
```

The VM will handle the actual implementation at runtime.

#### D. UFCS Support (`src/ufcs.rs`)

Already handled - `ClientStore.fill_object(obj, 0)` will transform to `fill_object(ClientStore, obj, 0)`.

### 4. **VM Integration**

The VM needs to implement the `fill_object` operation:

```
CALL fill_object:
  1. Pop client_idx from stack
  2. Pop object reference from stack
  3. Pop ClientStore reference from stack
  4. Inspect object type metadata to find secret fields
  5. For each secret field (in order):
     - Retrieve share from client at (client_idx, share_idx)
     - Assign to object's secret field
     - Increment share_idx
  6. Return
```

### 5. **Testing Requirements**

Create test files:

- **`tests/fill_object_valid.stfl`**:
  ```stoffel
  object Person:
    name: string
    age: int64
    secret ssn: secret int64
    secret salary: secret int64

  def main() -> nil:
    var person = Person()
    person.name = "Alice"
    person.age = 30

    # Fill secret fields from client 0
    ClientStore.fill_object(person, 0)
    # person.ssn = share[0][0]
    # person.salary = share[0][1]

    print("Person created with secret data")
  ```

- **`tests/fill_object_invalid.stfl`**:
  ```stoffel
  object PublicData:
    value1: int64
    value2: int64

  object PrivateData:
    secret value: secret int64

  def main() -> nil:
    # ERROR: Cannot fill immutable object
    let data = PrivateData()
    ClientStore.fill_object(data, 0)

    # ERROR: Object has no secret fields
    var public_data = PublicData()
    ClientStore.fill_object(public_data, 0)
  ```

### 6. **Error Messages**

Provide clear error messages:

- "Cannot use fill_object on immutable object. Use 'var' instead of 'let'"
- "Object type '<Type>' has no secret fields to fill"
- "fill_object requires an object type, found '<Type>'"
- "Invalid client index type. Expected int64, found '<Type>'"

## Implementation Phases

### Phase 1: Object Support (Foundation)
1. Implement object definition parsing
2. Implement object instantiation
3. Implement field access and assignment
4. Add object types to symbol table
5. Implement semantic validation for objects
6. Implement code generation for objects

### Phase 2: fill_object Method
1. Add `fill_object` to builtin functions
2. Implement semantic validation (steps outlined above)
3. Register as known builtin in codegen
4. Create comprehensive tests

### Phase 3: VM Integration
1. Implement runtime support in VM
2. Handle object metadata inspection
3. Implement share retrieval and assignment

## Alternative: Simpler Approach

If full object support is too complex, consider a simpler API:

```stoffel
# Instead of fill_object, use individual assignments
var field1 = ClientStore.take_share(0, 0)
var field2 = ClientStore.take_share(0, 1)

# Or a macro-like expansion
@fill_from_client(0)
object UserData:
  public_id: int64
  secret_value: secret int64  # Auto-filled from share[0][0]
  secret_balance: secret int64 # Auto-filled from share[0][1]
```

## Summary

**Core Dependencies:**
1. ✓ UFCS transformation (already working)
2. ✗ Object/struct definition and instantiation (needs implementation)
3. ✗ Field access and assignment (needs implementation)
4. ✗ Object type tracking in symbol table (needs implementation)
5. ✓ Builtin function registration (already working)

**Estimated Complexity:** Medium-High (requires full object system)

**Recommendation:** Start by implementing basic object support first, then add `fill_object` as an enhancement.
