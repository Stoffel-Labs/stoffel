# Local Nested Generics

Exercises generic functions over nested list types and runs entirely locally.
The example verifies that `list[list[T]]` works when `T` is a scalar, a list,
or a deeper nested list. It also uses `items[index]` with a runtime index
through a generic `at[T]` helper, and validates that the emitted bytecode
executes in StoffelVM.

Expected return value: `37`.
