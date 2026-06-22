# Local Closure Counter

Builds a stateful counter callback with a captured upvalue. The example is a
small local workflow for retry budgets, rolling limits, or progress counters:
one function creates a closure over the starting value, and the callback reads
and updates that captured value each time it runs.

This covers `create_closure_with_upvalue`, `call_closure_with_arg`,
`get_upvalue`, and `set_upvalue`.
