//! Interprocedural client-I/O inference over the checked AST.
//!
//! Input planning propagates concrete slots/ordinals through relevant helpers.
//! Output planning tracks share tags, exact scalar widths, aggregate identities,
//! aliases, and mutations through helper calls. Static loops are enumerated;
//! runtime loop backedges are joined to a bounded fixed point. Unprovable output
//! domains or batch lengths produce source diagnostics instead of guessed tags.
//! The proven output contract replaces codegen's local guesses after lowering.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use crate::ast::{AstNode, Parameter, Pragma, Value};
use crate::errors::{CompilerError, SourceLocation};
use crate::symbol_table::SymbolType;
use stoffel_vm_types::compiled_binary::{
    ClientIoManifest, ClientIoSchema, DynamicClientInputSchema,
};
use stoffel_vm_types::core_types::ShareType;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct AbstractValue {
    list_depth: usize,
    opaque: bool,
    float: bool,
    share: Option<ShareType>,
    aggregate: Option<usize>,
    int: Option<i128>,
    list_len: Option<usize>,
    runtime_client_count: bool,
    dynamic_client_slot_start: Option<u64>,
}

impl AbstractValue {
    fn int(value: i128) -> Self {
        Self {
            list_depth: 0,
            opaque: false,
            float: false,
            share: None,
            aggregate: None,
            int: Some(value),
            list_len: None,
            runtime_client_count: false,
            dynamic_client_slot_start: None,
        }
    }

    fn list(len: usize) -> Self {
        Self {
            list_depth: 1,
            opaque: false,
            float: false,
            share: None,
            aggregate: None,
            int: None,
            list_len: Some(len),
            runtime_client_count: false,
            dynamic_client_slot_start: None,
        }
    }
}

// Names live in the immutable AST for the entire planning pass. Borrow them so
// branch/backedge snapshots copy values without allocating one string per local.
type Env<'a> = crate::snapshot_env::SnapshotEnv<'a, AbstractValue>;
type InferredInputs = HashMap<u64, Vec<Option<ShareType>>>;
type InferredDynamicInputs = HashMap<u64, Vec<Option<ShareType>>>;
type InferredOutputCounts = HashMap<u64, usize>;
type InferredOutputs = HashMap<u64, Vec<Option<ShareType>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Aggregate {
    Unknown,
    Closure(String),
    List(Vec<AbstractValue>),
    Object(HashMap<String, AbstractValue>),
}

// Snapshots share immutable pages. Only a page written after a snapshot is
// copied, and merges can skip every page still shared with their input state.
// Keep aggregate identities append-only, including allocations on either branch.
const HEAP_PAGE_SIZE: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Heap {
    pages: Vec<Rc<Vec<Aggregate>>>,
    len: usize,
}

impl Heap {
    fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, value: Aggregate) {
        if self.len.is_multiple_of(HEAP_PAGE_SIZE) {
            self.pages.push(Rc::new(Vec::with_capacity(HEAP_PAGE_SIZE)));
        }
        Rc::make_mut(self.pages.last_mut().unwrap()).push(value);
        self.len += 1;
    }

    fn get(&self, id: usize) -> Option<&Aggregate> {
        (id < self.len).then(|| &self.pages[id / HEAP_PAGE_SIZE][id % HEAP_PAGE_SIZE])
    }

    fn get_mut(&mut self, id: usize) -> Option<&mut Aggregate> {
        if id >= self.len {
            return None;
        }
        Some(&mut Rc::make_mut(&mut self.pages[id / HEAP_PAGE_SIZE])[id % HEAP_PAGE_SIZE])
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut Aggregate> {
        self.pages
            .iter_mut()
            .flat_map(|page| Rc::make_mut(page).iter_mut())
    }

    fn restore_prefix(&mut self, before: &Self) {
        let full = before.len / HEAP_PAGE_SIZE;
        self.pages[..full].clone_from_slice(&before.pages[..full]);
        let tail = before.len % HEAP_PAGE_SIZE;
        if tail != 0 {
            if self.len == before.len {
                self.pages[full] = Rc::clone(&before.pages[full]);
            } else {
                Rc::make_mut(&mut self.pages[full])[..tail]
                    .clone_from_slice(&before.pages[full][..tail]);
            }
        }
    }

    fn changed_ids(&self, after: &Self) -> Vec<usize> {
        let mut changed = Vec::new();
        for (page_index, page) in self.pages.iter().enumerate() {
            let other = &after.pages[page_index];
            if !Rc::ptr_eq(page, other) {
                for (offset, value) in page.iter().enumerate() {
                    if value != &other[offset] {
                        changed.push(page_index * HEAP_PAGE_SIZE + offset);
                    }
                }
            }
        }
        changed
    }
}

impl std::ops::Index<usize> for Heap {
    type Output = Aggregate;

    fn index(&self, id: usize) -> &Aggregate {
        self.get(id).expect("valid aggregate id")
    }
}

impl std::ops::IndexMut<usize> for Heap {
    fn index_mut(&mut self, id: usize) -> &mut Aggregate {
        self.get_mut(id).expect("valid aggregate id")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Control {
    #[default]
    Next,
    Return,
    Break,
    Continue,
}

struct FunctionInfo<'a> {
    parameters: &'a [Parameter],
    parameter_types: Rc<[Option<SymbolType>]>,
    body: &'a AstNode,
    is_entry: bool,
    returns_list: bool,
    return_type: Option<SymbolType>,
}

struct LoopSnapshot<'a> {
    env: Env<'a>,
    heap: Heap,
    offsets: HashMap<u64, BTreeSet<usize>>,
}

#[derive(Default)]
struct LoopFrame<'a> {
    breaks: Vec<LoopSnapshot<'a>>,
    continues: Vec<LoopSnapshot<'a>>,
}

#[derive(Default)]
struct Planner<'a> {
    functions: HashMap<String, FunctionInfo<'a>>,
    relevant: HashSet<String>,
    domain_sensitive: HashSet<String>,
    inputs: InferredInputs,
    dynamic_inputs: InferredDynamicInputs,
    output_counts: InferredOutputCounts,
    call_stack: Vec<(String, Vec<AbstractValue>)>,
    scalar_cache: HashMap<(String, Vec<AbstractValue>), AbstractValue>,
    heap: Heap,
    uncertain_lengths: HashSet<usize>,
    aggregate_aliases: HashMap<usize, BTreeSet<usize>>,
    // Reverse edges contain only original referents; proxy ids are append-only.
    alias_dependents: HashMap<usize, Vec<usize>>,
    outputs: InferredOutputs,
    output_offsets: HashMap<u64, BTreeSet<usize>>,
    object_types: HashMap<String, Vec<crate::ast::FieldDefinition>>,
    errors: Vec<CompilerError>,
    output_locations: HashMap<u64, SourceLocation>,
    control: Control,
    loops: Vec<LoopFrame<'a>>,
    returns: Vec<AbstractValue>,
    steps: usize,
    integer_invariants: Option<Box<IntegerInvariants>>,
    needs_output_shapes: bool,
}

// Only exact, plain integer arithmetic is cached. Aggregate facts and calls
// remain dynamic; writes anywhere in the loop exclude a binding entirely.
type IntegerInvariants = [Option<(*const AstNode, i128, usize)>; 32];

fn loop_integer_invariants<'a>(
    condition: &'a AstNode,
    body: &'a AstNode,
    env: &Env<'a>,
) -> Option<Box<IntegerInvariants>> {
    fn writes<'a>(node: &'a AstNode, names: &mut HashSet<&'a str>) {
        match node {
            AstNode::VariableDeclaration { name, .. } => {
                names.insert(name);
            }
            AstNode::Assignment { target, .. } => {
                if let AstNode::Identifier(name, _) = target.as_ref() {
                    names.insert(name);
                }
            }
            AstNode::ForLoop { variables, .. } => {
                names.extend(variables.iter().map(String::as_str))
            }
            _ => {}
        }
        crate::optimizations::for_each_child(node, &mut |child| writes(child, names));
    }
    fn gather(
        node: &AstNode,
        env: &Env<'_>,
        writes: &HashSet<&str>,
        cache: &mut IntegerInvariants,
    ) -> Option<(i128, usize)> {
        let value = match node {
            AstNode::Literal {
                value: Value::Int { value, .. },
                ..
            } => i128::try_from(*value).ok().map(|v| (v, 1)),
            AstNode::Literal {
                value: Value::Bool(value),
                ..
            } => Some((i128::from(*value), 1)),
            AstNode::Identifier(name, _) if !writes.contains(name.as_str()) => env
                .get(name)
                .and_then(|value| value.int.filter(|&n| *value == AbstractValue::int(n)))
                .map(|v| (v, 1)),
            AstNode::BinaryOperation {
                op, left, right, ..
            } => {
                let left = gather(left, env, writes, cache);
                let right = gather(right, env, writes, cache);
                left.zip(right).and_then(|((a, ac), (b, bc))| {
                    eval_binary(op, Some(a), Some(b)).map(|v| (v, 1 + ac + bc))
                })
            }
            AstNode::UnaryOperation { op, operand, .. } => gather(operand, env, writes, cache)
                .and_then(|(value, cost)| {
                    let result = match op.as_str() {
                        "-" => value.checked_neg(),
                        "+" => Some(value),
                        "not" => Some(i128::from(value == 0)),
                        "~" => Some(!value),
                        _ => None,
                    };
                    result.map(|v| (v, cost + 1))
                }),
            _ => {
                crate::optimizations::for_each_child(node, &mut |child| {
                    gather(child, env, writes, cache);
                });
                None
            }
        };
        if let Some((value, cost)) = value {
            if cost > 1 {
                let key = node as *const AstNode;
                cache[((key as usize) >> 4) & 31] = Some((key, value, cost));
            }
        }
        value
    }
    let mut mutated = HashSet::new();
    writes(condition, &mut mutated);
    writes(body, &mut mutated);
    let mut cache = Box::new([None; 32]);
    gather(condition, env, &mutated, &mut cache);
    gather(body, env, &mutated, &mut cache);
    cache.iter().any(Option::is_some).then_some(cache)
}

const MAX_STATIC_LOOP_ITERATIONS: usize = 1_000_000;

/// Add interprocedurally inferred client inputs to an already generated
/// manifest. Existing output schemas and directly inferred input types remain
/// intact.
pub(crate) fn merge_inferred_client_inputs(program: &AstNode, manifest: &mut ClientIoManifest) {
    let (inputs, dynamic_inputs, output_counts) = infer_client_io(program);
    for (client_slot, inferred) in inputs {
        let schema = match manifest
            .clients
            .iter_mut()
            .find(|schema| schema.client_slot == client_slot)
        {
            Some(schema) => schema,
            None => {
                manifest.clients.push(ClientIoSchema {
                    client_slot,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                });
                manifest
                    .clients
                    .last_mut()
                    .expect("client schema was pushed")
            }
        };
        let directly_inferred_len = schema.inputs.len();
        if schema.inputs.len() < inferred.len() {
            schema
                .inputs
                .resize_with(inferred.len(), ShareType::default_secret_int);
        }
        for (ordinal, share_type) in inferred.into_iter().enumerate() {
            if let Some(share_type) = share_type {
                // Direct codegen has semantic annotations and is authoritative
                // for every ordinal it already found. The concrete planner only
                // fills ordinals discovered through helper-call propagation;
                // otherwise its builtin defaults would erase precise types such
                // as an annotated `secret fix32`.
                if ordinal >= directly_inferred_len {
                    schema.inputs[ordinal] = share_type;
                }
            }
        }
    }
    manifest
        .clients
        .sort_unstable_by_key(|schema| schema.client_slot);

    for (first_client_slot, inferred) in dynamic_inputs {
        let schema = match manifest
            .dynamic_client_inputs
            .iter_mut()
            .find(|schema| schema.first_client_slot == first_client_slot)
        {
            Some(schema) => schema,
            None => {
                manifest
                    .dynamic_client_inputs
                    .push(DynamicClientInputSchema {
                        first_client_slot,
                        inputs: Vec::new(),
                    });
                manifest
                    .dynamic_client_inputs
                    .last_mut()
                    .expect("dynamic client input schema was pushed")
            }
        };
        if schema.inputs.len() < inferred.len() {
            schema
                .inputs
                .resize_with(inferred.len(), ShareType::default_secret_int);
        }
        for (ordinal, share_type) in inferred.into_iter().enumerate() {
            if let Some(share_type) = share_type {
                schema.inputs[ordinal] = share_type;
            }
        }
    }
    manifest
        .dynamic_client_inputs
        .sort_unstable_by_key(|schema| schema.first_client_slot);

    // Codegen visits a loop body once, so a `send_to_client` inside a bounded
    // loop contributes only one schema output even though the VM captures one
    // output per iteration. The concrete walk below enumerates bounded loops
    // and user-function calls. Extend the direct type pattern to the inferred
    // cardinality; the standing runner can then submit the complete ordered
    // batch once, matching the coordinator contract.
    for (client_slot, inferred_count) in output_counts {
        let schema = match manifest
            .clients
            .iter_mut()
            .find(|schema| schema.client_slot == client_slot)
        {
            Some(schema) => schema,
            None => {
                manifest.clients.push(ClientIoSchema {
                    client_slot,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                });
                manifest
                    .clients
                    .last_mut()
                    .expect("client schema was pushed")
            }
        };
        if schema.outputs.len() < inferred_count {
            let pattern = if schema.outputs.is_empty() {
                vec![ShareType::default_secret_int()]
            } else {
                schema.outputs.clone()
            };
            while schema.outputs.len() < inferred_count {
                let next = pattern[schema.outputs.len() % pattern.len()];
                schema.outputs.push(next);
            }
        }
    }
    manifest
        .clients
        .sort_unstable_by_key(|schema| schema.client_slot);
}

fn infer_client_io(
    program: &AstNode,
) -> (InferredInputs, InferredDynamicInputs, InferredOutputCounts) {
    let planner = plan_client_io(program, &[], false);
    (
        planner.inputs,
        planner.dynamic_inputs,
        planner.output_counts,
    )
}

fn plan_client_io<'a>(
    program: &'a AstNode,
    entry_points: &[String],
    infer_output_shapes: bool,
) -> Planner<'a> {
    // With no client operations anywhere in the checked program, all inferred
    // schemas are empty. In particular, do not abstractly execute large
    // inlined/unrolled circuits just to rediscover that fact. Scan every
    // function, including closure targets and additional entrypoints, rather
    // than assuming that only `main` can perform I/O.
    if !has_client_io(program) {
        return Planner::default();
    }
    let mut functions = HashMap::new();
    collect_functions(program, &mut functions);

    let mut direct_client_readers = HashSet::new();
    let mut callees: HashMap<String, HashSet<String>> = HashMap::new();
    for (name, info) in &functions {
        let mut calls = HashSet::new();
        let mut reads_client = false;
        collect_calls(info.body, &mut calls, &mut reads_client);
        if reads_client {
            direct_client_readers.insert(name.clone());
        }
        callees.insert(name.clone(), calls);
    }

    // Fixed-point reachability over the call graph lets the interpreter skip
    // large unrelated circuits (notably AES itself) and visit only helpers that
    // can eventually read from ClientStore.
    let mut domain_sensitive = HashSet::new();
    for (name, info) in &functions {
        if info.parameters.iter().any(|p| p.type_annotation.as_deref().map(SymbolType::from_ast).is_some_and(|ty| matches!(ty.underlying_type(), SymbolType::Object(n) | SymbolType::TypeName(n) if n == "Share")))
            || callees[name].iter().any(|callee| matches!(callee.as_str(), "Share.from_field" | "Share.random_field" | "Share.add_field" | "Share.mul_field" | "add_field" | "mul_field" | "Share.from_clear_int" | "Share.from_clear_uint" | "Share.from_clear_fixed" | "Share.retag" | "retag" | "Share.mul_scalar" | "mul_scalar" | "Share.add_constant" | "add_constant" | "Share.add_scalar" | "add_scalar")) {
            domain_sensitive.insert(name.clone());
        }
    }
    loop {
        let before = domain_sensitive.len();
        for (caller, calls) in &callees {
            if calls.iter().any(|callee| domain_sensitive.contains(callee)) {
                domain_sensitive.insert(caller.clone());
            }
        }
        if before == domain_sensitive.len() {
            break;
        }
    }
    let mut relevant = direct_client_readers;
    loop {
        let before = relevant.len();
        for (caller, calls) in &callees {
            if calls.iter().any(|callee| relevant.contains(callee)) {
                relevant.insert(caller.clone());
            }
        }
        if relevant.len() == before {
            break;
        }
    }

    let entries = functions
        .iter()
        .filter_map(|(name, info)| {
            (name == "main" || info.is_entry || entry_points.contains(name)).then_some(name.clone())
        })
        .collect::<Vec<_>>();

    let mut needs_output_shapes = false;
    fn has_outputs(node: &AstNode, found: &mut bool) {
        match node {
            AstNode::FunctionDefinition { body, .. } => has_outputs(body, found),
            AstNode::FunctionCall { function, .. } if matches!(function.as_ref(), AstNode::Identifier(name, _) if is_client_output_call(name)) => {
                *found = true
            }
            _ => {}
        }
        crate::optimizations::for_each_child(node, &mut |child| has_outputs(child, found));
    }
    if infer_output_shapes {
        has_outputs(program, &mut needs_output_shapes);
    }
    fn collect_objects(
        node: &AstNode,
        out: &mut HashMap<String, Vec<crate::ast::FieldDefinition>>,
    ) {
        if let AstNode::ObjectDefinition { name, fields, .. } = node {
            out.insert(name.clone(), fields.clone());
        }
        if let AstNode::FunctionDefinition { body, .. } = node {
            collect_objects(body, out);
        }
        crate::optimizations::for_each_child(node, &mut |child| collect_objects(child, out));
    }
    let mut object_types = HashMap::new();
    collect_objects(program, &mut object_types);
    let mut planner = Planner {
        functions,
        relevant,
        domain_sensitive,
        inputs: HashMap::new(),
        dynamic_inputs: HashMap::new(),
        output_counts: HashMap::new(),
        call_stack: Vec::new(),
        scalar_cache: HashMap::new(),
        heap: Heap::default(),
        uncertain_lengths: HashSet::new(),
        aggregate_aliases: HashMap::new(),
        alias_dependents: HashMap::new(),
        outputs: HashMap::new(),
        output_offsets: HashMap::new(),
        object_types,
        errors: Vec::new(),
        output_locations: HashMap::new(),
        control: Control::Next,
        loops: Vec::new(),
        returns: Vec::new(),
        steps: 0,
        integer_invariants: None,
        needs_output_shapes,
    };

    // Top-level executable statements are an entry form too. Function
    // definitions are scope declarations and are skipped by `visit`.
    planner.visit(program, &mut Env::new());
    for (index, entry) in entries.iter().enumerate() {
        planner.output_offsets.clear();
        // Only the final entry may omit its unused tail: earlier entries still
        // consume the same shared visitor budget before the next entry runs.
        planner.visit_user_call(entry, &[], index + 1 == entries.len());
    }
    planner
}

fn has_client_io(node: &AstNode) -> bool {
    match node {
        AstNode::FunctionDefinition {
            body, parameters, ..
        } => {
            return has_client_io(body)
                || parameters.iter().any(|parameter| {
                    parameter
                        .default_value
                        .as_deref()
                        .is_some_and(has_client_io)
                });
        }
        AstNode::FunctionCall { function, .. }
        | AstNode::CommandCall {
            command: function, ..
        } => {
            if matches!(function.as_ref(), AstNode::Identifier(name, _)
                if is_client_input_call(name) || is_client_output_call(name))
            {
                return true;
            }
        }
        _ => {}
    }
    let mut found = false;
    crate::optimizations::for_each_child(node, &mut |child| {
        if !found {
            found = has_client_io(child);
        }
    });
    found
}

/// Resolve output domains from actual calls before optimization erases source
/// structure. Unknown domains are errors, never an implicit integer encoding.
pub(crate) fn infer_output_domains(
    program: &AstNode,
    entry_points: &[String],
) -> Result<HashMap<u64, Vec<ShareType>>, Vec<CompilerError>> {
    let mut planner = plan_client_io(program, entry_points, true);
    let mut outputs = HashMap::new();
    for (slot, values) in planner.outputs {
        if let Some(types) = values.into_iter().collect::<Option<Vec<_>>>() {
            outputs.insert(slot, types);
        } else {
            planner.errors.push(CompilerError::type_error(
                "Cannot infer a single share domain for this client output",
                planner.output_locations.get(&slot).cloned().unwrap_or_default())
                .with_hint("Use an explicit Share constructor or a secret scalar type; every possible value at an output position must have the same domain and precision"));
        }
    }
    if planner.errors.is_empty() {
        Ok(outputs)
    } else {
        Err(planner.errors)
    }
}

pub(crate) fn apply_output_domains(
    outputs: HashMap<u64, Vec<ShareType>>,
    manifest: &mut ClientIoManifest,
) {
    for schema in &mut manifest.clients {
        schema.outputs.clear();
    }
    for (slot, outputs) in outputs {
        if let Some(schema) = manifest.clients.iter_mut().find(|s| s.client_slot == slot) {
            schema.outputs = outputs;
        } else {
            manifest.clients.push(ClientIoSchema {
                client_slot: slot,
                inputs: Vec::new(),
                outputs,
            });
        }
    }
    manifest.clients.sort_unstable_by_key(|s| s.client_slot);
}

fn collect_functions<'a>(node: &'a AstNode, out: &mut HashMap<String, FunctionInfo<'a>>) {
    match node {
        AstNode::FunctionDefinition {
            name: Some(name),
            parameters,
            return_type,
            body,
            pragmas,
            ..
        } => {
            out.insert(
                name.clone(),
                FunctionInfo {
                    parameter_types: parameters
                        .iter()
                        .map(|p| p.type_annotation.as_deref().map(SymbolType::from_ast))
                        .collect(),
                    parameters,
                    body,
                    is_entry: pragmas
                        .iter()
                        .any(|pragma| matches!(pragma, Pragma::Simple(name, _) if name == "entry")),
                    returns_list: return_type.as_deref().is_some_and(is_list_return_type),
                    return_type: return_type.as_deref().map(SymbolType::from_ast),
                },
            );
            collect_functions(body, out);
        }
        AstNode::Block(nodes) => {
            for node in nodes {
                collect_functions(node, out);
            }
        }
        _ => {}
    }
}

fn collect_calls(node: &AstNode, calls: &mut HashSet<String>, reads_client: &mut bool) {
    if let AstNode::FunctionCall {
        function,
        arguments,
        ..
    }
    | AstNode::CommandCall {
        command: function,
        arguments,
        ..
    } = node
    {
        if let AstNode::Identifier(name, _) = function.as_ref() {
            if is_client_input_call(name) || is_client_output_call(name) {
                *reads_client = true;
            } else {
                calls.insert(name.clone());
                if matches!(
                    name.as_str(),
                    "create_closure" | "create_closure_with_upvalue"
                ) {
                    if let Some(AstNode::Literal {
                        value: Value::String(target),
                        ..
                    }) = arguments.first()
                    {
                        calls.insert(target.clone());
                    }
                }
            }
        }
    }
    crate::optimizations::for_each_child(node, &mut |child| {
        collect_calls(child, calls, reads_client)
    });
}

impl<'a> Planner<'a> {
    fn may_perform_client_io(&self, node: &AstNode) -> bool {
        if let AstNode::FunctionCall { function, .. }
        | AstNode::CommandCall {
            command: function, ..
        } = node
        {
            match function.as_ref() {
                AstNode::Identifier(name, _) => {
                    if is_client_input_call(name)
                        || is_client_output_call(name)
                        || self.relevant.contains(name)
                        || matches!(name.as_str(), "call_closure" | "call_closure_with_arg")
                    {
                        return true;
                    }
                }
                _ => return true,
            }
        }
        let mut found = false;
        crate::optimizations::for_each_child(node, &mut |child| {
            found = found || self.may_perform_client_io(child);
        });
        found
    }

    fn visit_statements(&mut self, nodes: &'a [AstNode], env: &mut Env<'a>) -> AbstractValue {
        let mut value = AbstractValue::default();
        for node in nodes {
            if self.control != Control::Next {
                break;
            }
            if !matches!(node, AstNode::FunctionDefinition { .. }) {
                value = self.visit(node, env);
            }
        }
        value
    }

    fn visit(&mut self, node: &'a AstNode, env: &mut Env<'a>) -> AbstractValue {
        self.steps += 1;
        if self.steps > 5_000_000 {
            if self.steps == 5_000_001 && self.needs_output_shapes {
                self.errors.push(CompilerError::type_error("Share-domain inference exceeded its analysis budget", node.location()).with_hint("Simplify the output-producing loop or split the entrypoint into smaller computations"));
            }
            return AbstractValue {
                opaque: true,
                ..AbstractValue::default()
            };
        }
        if matches!(
            node,
            AstNode::BinaryOperation { .. } | AstNode::UnaryOperation { .. }
        ) {
            if let Some(cache) = &self.integer_invariants {
                let key = node as *const AstNode;
                if let Some((cached, value, cost)) = cache[((key as usize) >> 4) & 31] {
                    if cached == key && self.steps + cost - 1 <= 5_000_000 {
                        self.steps += cost - 1;
                        return AbstractValue::int(value);
                    }
                }
            }
        }
        match node {
            AstNode::Literal { value, .. } => match value {
                Value::Int { value, .. } => i128::try_from(*value)
                    .map(AbstractValue::int)
                    .unwrap_or_default(),
                Value::Float(_) => AbstractValue {
                    float: true,
                    ..AbstractValue::default()
                },
                Value::Bool(value) => AbstractValue::int(i128::from(*value)),
                _ => AbstractValue::default(),
            },
            AstNode::Identifier(name, _) => env.get_ast(name.as_str()).copied().unwrap_or_default(),
            AstNode::VariableDeclaration {
                name,
                value,
                type_annotation,
                ..
            } => {
                let has_initializer = value.is_some();
                let mut value = value
                    .as_deref()
                    .map(|value| self.visit(value, env))
                    .unwrap_or_default();
                if let Some(ty) = type_annotation.as_deref().map(SymbolType::from_ast) {
                    value = self.apply_type(value, &ty);
                    if !has_initializer {
                        value = self.default_value(&ty, 0);
                    }
                }
                env.insert(name.as_str(), value);
                value
            }
            AstNode::Assignment { target, value, .. } => {
                let value = self.visit(value, env);
                if let AstNode::Identifier(name, _) = target.as_ref() {
                    env.insert(name.as_str(), value);
                } else {
                    self.assign_aggregate(target, value, env);
                }
                value
            }
            AstNode::BinaryOperation {
                op, left, right, ..
            } => {
                let left = self.visit(left, env);
                let right = self.visit(right, env);
                if op == "*" {
                    if let Some(result) = self
                        .repeat_list(left, right)
                        .or_else(|| self.repeat_list(right, left))
                    {
                        return result;
                    }
                }
                if op == "+" {
                    if let (Some(Aggregate::List(a)), Some(Aggregate::List(b))) = (
                        left.aggregate.and_then(|id| self.heap.get(id)),
                        right.aggregate.and_then(|id| self.heap.get(id)),
                    ) {
                        return self.list(a.iter().chain(b).copied().collect());
                    }
                }
                AbstractValue {
                    share: if (left.opaque && left.share.is_none())
                        || (right.opaque && right.share.is_none())
                    {
                        None
                    } else {
                        promoted_scalar_domain(
                            arithmetic_domain(op, left.share, right.share),
                            matches!(op.as_str(), "+" | "-" | "*" | "/")
                                && (left.float || right.float),
                        )
                    },
                    opaque: left.opaque
                        || right.opaque
                        || left.share.is_some()
                        || right.share.is_some(),
                    float: left.float || right.float,
                    int: eval_binary(op, left.int, right.int),
                    list_len: None,
                    ..AbstractValue::default()
                }
            }
            AstNode::UnaryOperation { op, operand, .. } => {
                let value = self.visit(operand, env);
                let int = match (op.as_str(), value.int) {
                    ("-", Some(value)) => value.checked_neg(),
                    ("+", value) => value,
                    ("not", Some(value)) => Some(i128::from(value == 0)),
                    ("~", Some(value)) => Some(!value),
                    _ => None,
                };
                AbstractValue {
                    share: value.share,
                    opaque: value.opaque,
                    float: value.float,
                    int,
                    list_len: None,
                    ..AbstractValue::default()
                }
            }
            AstNode::Block(nodes) => self.visit_statements(nodes, env),
            AstNode::FunctionDefinition { .. } => AbstractValue::default(),
            AstNode::FunctionCall {
                function,
                arguments,
                resolved_return_type,
                location,
            } => self.visit_call(
                function,
                arguments,
                resolved_return_type.as_ref(),
                env,
                location,
            ),
            AstNode::CommandCall {
                command: function,
                arguments,
                location,
                ..
            } => self.visit_call(function, arguments, None, env, location),
            AstNode::NamedArgument { value, .. } => self.visit(value, env),
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                ..
            } => {
                self.visit_for(variables, iterable, body, env);
                AbstractValue::default()
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                self.visit_while(condition, body, env);
                AbstractValue::default()
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                if let Some(value) = self.visit(condition, env).int {
                    return if value != 0 {
                        self.visit(then_branch, env)
                    } else {
                        else_branch
                            .as_deref()
                            .map(|b| self.visit(b, env))
                            .unwrap_or_default()
                    };
                }
                let original = env.clone();
                let heap_before = self.heap.clone();
                let outputs_before = self.output_counts.clone();
                let types_before = self.outputs.clone();
                let offsets_before = self.output_offsets.clone();
                let mut then_env = original.clone();
                let then_value = self.visit(then_branch, &mut then_env);
                let then_control = self.control;
                let then_heap = self.heap.clone();
                let then_outputs = self.output_counts.clone();
                let then_types = self.outputs.clone();
                let then_offsets = self.output_offsets.clone();
                self.output_counts.clone_from(&outputs_before);
                self.outputs.clone_from(&types_before);
                self.output_offsets.clone_from(&offsets_before);
                self.heap.restore_prefix(&heap_before);
                self.control = Control::Next;
                let mut else_env = original.clone();
                let else_value = else_branch
                    .as_deref()
                    .map(|branch| self.visit(branch, &mut else_env))
                    .unwrap_or_default();
                let else_control = self.control;
                let else_outputs = self.output_counts.clone();
                let else_types = self.outputs.clone();
                merge_branch_output_counts(
                    &mut self.output_counts,
                    &outputs_before,
                    &then_outputs,
                    &else_outputs,
                );
                self.outputs = merge_output_types(&then_types, &else_types);
                let else_offsets = self.output_offsets.clone();
                if then_control == Control::Next && else_control == Control::Next {
                    self.output_offsets = merge_offsets(&then_offsets, &else_offsets);
                } else if then_control == Control::Next {
                    self.output_offsets = then_offsets;
                } else {
                    self.output_offsets = else_offsets;
                }
                for id in then_heap
                    .changed_ids(&self.heap)
                    .into_iter()
                    .filter(|&id| id < heap_before.len())
                {
                    let then = &then_heap[id];
                    if different_list_lengths(then, &self.heap[id]) {
                        self.uncertain_lengths.insert(id);
                    }
                    self.heap[id] = self.join_aggregate(then, &self.heap[id].clone());
                }
                match (then_control, else_control) {
                    (Control::Next, Control::Next) => {
                        self.merge_env(env, &then_env, &else_env);
                        self.control = Control::Next;
                    }
                    (Control::Next, _) => {
                        *env = then_env;
                        self.control = Control::Next;
                    }
                    (_, Control::Next) => {
                        *env = else_env;
                        self.control = Control::Next;
                    }
                    (a, b) => {
                        self.control = if a == b { a } else { Control::Return };
                    }
                }
                self.join_value(then_value, else_value)
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => {
                let values = elements
                    .iter()
                    .map(|element| self.visit(element, env))
                    .collect();
                self.list(values)
            }
            AstNode::DictLiteral { pairs, .. } => {
                for (key, value) in pairs {
                    self.visit(key, env);
                    self.visit(value, env);
                }
                AbstractValue::default()
            }
            AstNode::Return { value, .. } | AstNode::Yield(value) => {
                let value = value
                    .as_deref()
                    .map(|value| self.visit(value, env))
                    .unwrap_or_default();
                self.returns.push(value);
                self.control = Control::Return;
                value
            }
            AstNode::DiscardStatement { expression, .. } => self.visit(expression, env),
            AstNode::IndexAccess { base, index, .. } => {
                let base = self.visit(base, env);
                let index = self
                    .visit(index, env)
                    .int
                    .and_then(|n| usize::try_from(n).ok());
                if let Some(Aggregate::List(values)) =
                    base.aggregate.and_then(|id| self.heap.get(id))
                {
                    if let Some(index) = index {
                        return values.get(index).copied().unwrap_or_default();
                    }
                    return values
                        .clone()
                        .into_iter()
                        .reduce(|a, b| self.join_value(a, b))
                        .unwrap_or_default();
                }
                AbstractValue {
                    list_depth: base.list_depth.saturating_sub(1),
                    opaque: base.opaque || base.aggregate.is_some(),
                    share: if base.aggregate.is_none() {
                        base.share
                    } else {
                        None
                    },
                    ..AbstractValue::default()
                }
            }
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                let object = self.visit(object, env);
                if let Some(Aggregate::Object(fields)) =
                    object.aggregate.and_then(|id| self.heap.get(id))
                {
                    return fields.get(field_name).copied().unwrap_or_default();
                }
                AbstractValue {
                    opaque: true,
                    ..AbstractValue::default()
                }
            }
            AstNode::TryCatch {
                try_block,
                catch_clauses,
                finally_block,
                ..
            } => {
                self.visit(try_block, env);
                for clause in catch_clauses {
                    self.visit(&clause.body, env);
                }
                if let Some(finally_block) = finally_block {
                    self.visit(finally_block, env);
                }
                AbstractValue::default()
            }
            // Type and declaration nodes do not execute client reads.
            AstNode::Break => {
                let snapshot = self.loop_snapshot(env);
                if let Some(frame) = self.loops.last_mut() {
                    frame.breaks.push(snapshot);
                }
                self.control = Control::Break;
                AbstractValue::default()
            }
            AstNode::Continue => {
                let snapshot = self.loop_snapshot(env);
                if let Some(frame) = self.loops.last_mut() {
                    frame.continues.push(snapshot);
                }
                self.control = Control::Continue;
                AbstractValue::default()
            }
            AstNode::TypeAlias { .. }
            | AstNode::BuiltinTypeDefinition { .. }
            | AstNode::BuiltinObjectDefinition { .. }
            | AstNode::ObjectDefinition { .. }
            | AstNode::EnumDefinition { .. }
            | AstNode::SecretType(_)
            | AstNode::FunctionType { .. }
            | AstNode::TupleType(_)
            | AstNode::ListType(_)
            | AstNode::DictType { .. }
            | AstNode::GenericType { .. }
            | AstNode::Import { .. } => AbstractValue::default(),
        }
    }

    fn visit_call(
        &mut self,
        function: &'a AstNode,
        arguments: &'a [AstNode],
        resolved_return_type: Option<&SymbolType>,
        env: &mut Env<'a>,
        location: &SourceLocation,
    ) -> AbstractValue {
        // ponytail: common calls fit four values; larger calls use the existing
        // vector path. Both evaluate arguments exactly once, left to right.
        let mut local = [AbstractValue::default(); 4];
        let spill;
        let argument_values: &[AbstractValue] = if arguments.len() <= local.len() {
            for (slot, argument) in local.iter_mut().zip(arguments) {
                *slot = self.visit(argument, env);
            }
            &local[..arguments.len()]
        } else {
            spill = arguments
                .iter()
                .map(|argument| self.visit(argument, env))
                .collect::<Vec<_>>();
            &spill
        };
        let AstNode::Identifier(name, _) = function else {
            self.visit(function, env);
            return AbstractValue::default();
        };

        if matches!(
            name.as_str(),
            "create_closure" | "create_closure_with_upvalue"
        ) {
            if let Some(AstNode::Literal {
                value: Value::String(target),
                ..
            }) = arguments.first()
            {
                let id = self.heap.len();
                self.heap.push(Aggregate::Closure(target.clone()));
                return AbstractValue {
                    aggregate: Some(id),
                    ..AbstractValue::default()
                };
            }
        }
        if matches!(name.as_str(), "call_closure" | "call_closure_with_arg") {
            if let Some(Aggregate::Closure(target)) = argument_values
                .first()
                .and_then(|v| v.aggregate)
                .and_then(|id| self.heap.get(id))
                .cloned()
            {
                if self.functions.contains_key(&target) {
                    return self.visit_user_call(&target, &argument_values[1..], false);
                }
            }
            if self.needs_output_shapes {
                self.errors.push(CompilerError::type_error("Cannot infer the target of this closure call for client I/O", location.clone())
                    .with_hint("Use a statically named closure target or a direct helper call for output-producing computations"));
            }
            return AbstractValue {
                opaque: true,
                ..AbstractValue::default()
            };
        }
        if matches!(name.as_str(), "Share.batch_mul" | "batch_mul") {
            if let (Some(Aggregate::List(a)), Some(Aggregate::List(b))) = (
                argument_values
                    .first()
                    .and_then(|v| v.aggregate)
                    .and_then(|id| self.heap.get(id))
                    .cloned(),
                argument_values
                    .get(1)
                    .and_then(|v| v.aggregate)
                    .and_then(|id| self.heap.get(id))
                    .cloned(),
            ) {
                return self.list(
                    a.iter()
                        .zip(b)
                        .map(|(a, b)| AbstractValue {
                            share: arithmetic_domain("*", a.share, b.share),
                            ..AbstractValue::default()
                        })
                        .collect(),
                );
            }
        }
        if name == "ClientStore.get_number_clients" {
            return AbstractValue {
                runtime_client_count: true,
                ..AbstractValue::default()
            };
        } else if is_client_input_sum_call(name) {
            self.record_client_input_sum(name, argument_values, resolved_return_type);
        } else if is_client_input_call(name) {
            self.record_client_input(name, argument_values, resolved_return_type);
        } else if is_client_output_call(name) {
            self.record_client_output(name, argument_values);
            if self.needs_output_shapes {
                self.record_output_domains(name, argument_values, location);
            }
        } else if matches!(name.as_str(), "len" | "array_length") {
            return AbstractValue {
                int: argument_values
                    .first()
                    .and_then(|value| self.list_length(*value))
                    .and_then(|len| i128::try_from(len).ok()),
                list_len: None,
                ..AbstractValue::default()
            };
        } else if matches!(name.as_str(), "append" | "array_push" | "insert") {
            if let Some(AstNode::Identifier(receiver, _)) = arguments.first() {
                if let Some(value) = env.get_mut(receiver.as_str()) {
                    value.list_len = value.list_len.and_then(|len| len.checked_add(1));
                }
            }
        } else if name == "extend" {
            if let Some(AstNode::Identifier(receiver, _)) = arguments.first() {
                let extension_len = argument_values.get(1).and_then(|value| value.list_len);
                if let Some(value) = env.get_mut(receiver.as_str()) {
                    value.list_len = value
                        .list_len
                        .zip(extension_len)
                        .and_then(|(left, right)| left.checked_add(right));
                }
            }
        } else if self.relevant.contains(name)
            || self.functions.get(name).is_some_and(|info| {
                self.needs_output_shapes
                    && (self.domain_sensitive.contains(name)
                        || info.parameter_types.iter().zip(argument_values).any(
                            |(parameter, value)| {
                                value.aggregate.is_some()
                                || (value.opaque && value.share.is_none())
                                || parameter
                                    .as_ref()
                                    .and_then(|ty| {
                                        crate::codegen::share_type_for_secret_scalar_symbol_type(
                                            ty,
                                        )
                                    })
                                    .is_some_and(|expected| {
                                        value.share.is_some_and(|actual| actual != expected)
                                    })
                            },
                        )
                        || info.returns_list
                        || info.return_type.as_ref().is_none_or(|ty| {
                            crate::codegen::share_type_for_secret_scalar_symbol_type(ty).is_none()
                        }))
            })
        {
            return self.visit_user_call(name, argument_values, false);
        }
        if let Some(id) = argument_values.first().and_then(|v| v.aggregate) {
            match name.as_str() {
                "append" | "array_push" => {
                    if let (Some(Aggregate::List(values)), Some(value)) =
                        (self.heap.get_mut(id), argument_values.get(1))
                    {
                        values.push(*value);
                    }
                }
                "insert" => {
                    if let (Some(Aggregate::List(values)), Some(index), Some(value)) = (
                        self.heap.get_mut(id),
                        argument_values
                            .get(1)
                            .and_then(|v| v.int)
                            .and_then(|v| usize::try_from(v).ok()),
                        argument_values.get(2),
                    ) {
                        if index <= values.len() {
                            values.insert(index, *value);
                        }
                    }
                }
                "copy" => {
                    if let Some(Aggregate::List(values)) = self.heap.get(id).cloned() {
                        let value = self.list(values);
                        if self.uncertain_lengths.contains(&id) {
                            self.uncertain_lengths.insert(value.aggregate.unwrap());
                        }
                        return value;
                    }
                }
                "reverse" => {
                    if let Some(Aggregate::List(values)) = self.heap.get_mut(id) {
                        values.reverse();
                    }
                }
                "clear" => {
                    if let Some(Aggregate::List(values)) = self.heap.get_mut(id) {
                        values.clear();
                        self.uncertain_lengths.remove(&id);
                    }
                }
                "pop" => {
                    if let Some(Aggregate::List(values)) = self.heap.get(id).cloned() {
                        let index = argument_values.get(1).map(|v| v.int).unwrap_or(Some(-1));
                        let Some(index) = index else {
                            let joined = values
                                .iter()
                                .copied()
                                .reduce(|a, b| self.join_value(a, b))
                                .unwrap_or_default();
                            self.write_heap(
                                id,
                                Aggregate::List(vec![joined; values.len().saturating_sub(1)]),
                            );
                            return joined;
                        };
                        let index = if index < 0 {
                            index + values.len() as i128
                        } else {
                            index
                        };
                        if let Ok(index) = usize::try_from(index) {
                            if index < values.len() {
                                let mut values = values;
                                let result = values.remove(index);
                                self.write_heap(id, Aggregate::List(values));
                                return result;
                            }
                        }
                        // Invalid/unknown index cannot establish a domain.
                        return AbstractValue {
                            opaque: true,
                            ..AbstractValue::default()
                        };
                    }
                }
                "sort" | "remove" => {
                    if let Some(Aggregate::List(values)) = self.heap.get(id).cloned() {
                        let joined = values
                            .iter()
                            .copied()
                            .reduce(|a, b| self.join_value(a, b))
                            .unwrap_or_default();
                        self.heap[id] = Aggregate::List(vec![
                            joined;
                            values.len().saturating_sub(
                                usize::from(name == "remove")
                            )
                        ]);
                    }
                }
                "extend" => {
                    let extension = argument_values
                        .get(1)
                        .and_then(|v| v.aggregate)
                        .and_then(|id| self.heap.get(id))
                        .cloned();
                    if let (Some(Aggregate::List(values)), Some(Aggregate::List(extension))) =
                        (self.heap.get_mut(id), extension)
                    {
                        values.extend(extension);
                    }
                }
                _ => {}
            }
            if matches!(
                name.as_str(),
                "append"
                    | "array_push"
                    | "insert"
                    | "extend"
                    | "reverse"
                    | "clear"
                    | "sort"
                    | "remove"
            ) {
                self.write_heap(id, self.heap[id].clone());
            }
        }
        if self.object_types.contains_key(name) {
            let value = self.default_value(&SymbolType::Object(name.clone()), 0);
            if let Some(Aggregate::Object(fields)) =
                value.aggregate.and_then(|id| self.heap.get_mut(id))
            {
                for (arg, value) in arguments.iter().zip(argument_values) {
                    if let AstNode::NamedArgument { name, .. } = arg {
                        fields.insert(name.clone(), *value);
                    }
                }
            }
            return value;
        }
        self.builtin_value(name, argument_values, resolved_return_type)
    }

    fn visit_user_call(
        &mut self,
        name: &str,
        arguments: &[AbstractValue],
        discard_tail: bool,
    ) -> AbstractValue {
        let cacheable = !discard_tail
            && !self.relevant.contains(name)
            && arguments.iter().all(|a| a.aggregate.is_none());
        let cache_key = cacheable.then(|| (name.to_owned(), arguments.to_vec()));
        if let Some(key) = &cache_key {
            if let Some(value) = self.scalar_cache.get(key) {
                return *value;
            }
        }
        if self.call_stack.len() >= 64
            || self
                .call_stack
                .iter()
                .any(|(active, values)| active == name && values == arguments)
        {
            if self.domain_sensitive.contains(name) {
                return AbstractValue {
                    opaque: true,
                    ..AbstractValue::default()
                };
            }
            return self
                .functions
                .get(name)
                .and_then(|info| info.return_type.as_ref())
                .map(|ty| self.typed_value(ty))
                .unwrap_or_default();
        }
        let Some(info) = self.functions.get(name) else {
            return AbstractValue::default();
        };
        let parameters = info.parameters;
        let parameter_types = info.parameter_types.clone();
        let body = info.body;
        let return_type = info.return_type.clone();
        let mut env = Env::new();
        for (index, (parameter, ty)) in parameters.iter().zip(parameter_types.iter()).enumerate() {
            let value = arguments.get(index).copied().unwrap_or_else(|| {
                ty.as_ref()
                    .map(|ty| self.typed_value(ty))
                    .unwrap_or_default()
            });
            let value = ty
                .as_ref()
                .map(|ty| self.apply_type(value, ty))
                .unwrap_or(value);
            env.insert(parameter.name.as_str(), value);
        }
        let saved_control = self.control;
        let saved_returns = std::mem::take(&mut self.returns);
        self.control = Control::Next;
        self.call_stack.push((name.to_string(), arguments.to_vec()));
        let last = if let AstNode::Block(nodes) = body {
            if discard_tail && !self.needs_output_shapes {
                let end = nodes
                    .iter()
                    .rposition(|node| self.may_perform_client_io(node))
                    .map_or(0, |index| index + 1);
                self.steps += 1; // the block node itself
                if self.steps > 5_000_000 {
                    AbstractValue {
                        opaque: true,
                        ..AbstractValue::default()
                    }
                } else {
                    self.visit_statements(&nodes[..end], &mut env)
                }
            } else {
                self.visit(body, &mut env)
            }
        } else {
            self.visit(body, &mut env)
        };
        self.call_stack.pop();
        let returns = std::mem::replace(&mut self.returns, saved_returns);
        self.control = saved_control;
        let value = returns
            .into_iter()
            .reduce(|a, b| self.join_value(a, b))
            .unwrap_or(last);
        let value = return_type
            .as_ref()
            .map(|ty| self.apply_type(value, ty))
            .unwrap_or(value);
        if let Some(key) = cache_key.filter(|_| value.aggregate.is_none()) {
            self.scalar_cache.insert(key, value);
        }
        value
    }

    fn record_client_input(
        &mut self,
        name: &str,
        arguments: &[AbstractValue],
        resolved_return_type: Option<&SymbolType>,
    ) {
        let Some(ordinal) = arguments
            .get(1)
            .and_then(|value| value.int)
            .and_then(|value| usize::try_from(value).ok())
        else {
            return;
        };
        let share_type = resolved_return_type
            .and_then(crate::codegen::share_type_for_secret_scalar_symbol_type)
            .unwrap_or_else(|| match name {
                "ClientStore.take_share_fixed" => ShareType::default_secret_fixed_point(),
                "ClientStore.take_share_bool" => ShareType::boolean(),
                _ => ShareType::default_secret_int(),
            });
        let Some(client) = arguments.first() else {
            return;
        };
        let inputs =
            if let Some(client_slot) = client.int.and_then(|value| u64::try_from(value).ok()) {
                self.inputs.entry(client_slot).or_default()
            } else if let Some(first_client_slot) = client.dynamic_client_slot_start {
                self.dynamic_inputs.entry(first_client_slot).or_default()
            } else {
                return;
            };
        if inputs.len() <= ordinal {
            inputs.resize(ordinal + 1, None);
        }
        inputs[ordinal] = Some(share_type);
    }

    fn record_client_input_sum(
        &mut self,
        name: &str,
        arguments: &[AbstractValue],
        resolved_return_type: Option<&SymbolType>,
    ) {
        let Some(ordinal) = arguments
            .first()
            .and_then(|value| value.int)
            .and_then(|value| usize::try_from(value).ok())
        else {
            return;
        };
        let Some(client_count) = arguments.get(1) else {
            return;
        };
        let share_type = resolved_return_type
            .and_then(crate::codegen::share_type_for_secret_scalar_symbol_type)
            .unwrap_or_else(|| match name {
                "ClientStore.sum_shares_bool" => ShareType::boolean(),
                "ClientStore.sum_shares_fixed" => ShareType::default_secret_fixed_point(),
                _ => ShareType::default_secret_int(),
            });

        if client_count.runtime_client_count {
            let inputs = self.dynamic_inputs.entry(0).or_default();
            if inputs.len() <= ordinal {
                inputs.resize(ordinal + 1, None);
            }
            inputs[ordinal] = Some(share_type);
            return;
        }

        let Some(client_count) = client_count
            .int
            .and_then(|value| usize::try_from(value).ok())
        else {
            return;
        };
        for client_slot in 0..client_count.max(1) {
            let inputs = self.inputs.entry(client_slot as u64).or_default();
            if inputs.len() <= ordinal {
                inputs.resize(ordinal + 1, None);
            }
            inputs[ordinal] = Some(share_type);
        }
    }

    fn record_client_output(&mut self, name: &str, arguments: &[AbstractValue]) {
        let (slot_argument, width) = match name {
            "send_to_client" | "Share.send_to_client" => (arguments.get(1), 1),
            "MpcOutput.send_to_client" => (
                arguments.first(),
                arguments
                    .get(1)
                    .and_then(|value| value.list_len)
                    .unwrap_or(1),
            ),
            _ => return,
        };
        let Some(client_slot) = slot_argument
            .and_then(|value| value.int)
            .and_then(|value| u64::try_from(value).ok())
        else {
            return;
        };
        let count = self.output_counts.entry(client_slot).or_default();
        *count = count.saturating_add(width);
    }

    fn visit_for(
        &mut self,
        variables: &'a [String],
        iterable: &'a AstNode,
        body: &'a AstNode,
        env: &mut Env<'a>,
    ) {
        let mut names = HashSet::new();
        fn declarations<'a>(node: &'a AstNode, names: &mut HashSet<&'a str>) {
            if let AstNode::VariableDeclaration { name, .. } = node {
                names.insert(name.as_str());
            }
            crate::optimizations::for_each_child(node, &mut |child| declarations(child, names));
        }
        declarations(body, &mut names);
        names.extend(variables.iter().map(String::as_str));
        let bindings: Vec<_> = names
            .into_iter()
            .map(|name| {
                let value = env.get(name).copied();
                (name, value)
            })
            .collect();
        self.loops.push(LoopFrame::default());
        self.visit_for_inner(variables, iterable, body, env);
        self.finish_loop(env);
        for (name, value) in bindings {
            if let Some(value) = value {
                env.insert(name, value);
            } else {
                env.remove(name);
            }
        }
    }

    fn visit_for_inner(
        &mut self,
        variables: &'a [String],
        iterable: &'a AstNode,
        body: &'a AstNode,
        env: &mut Env<'a>,
    ) {
        if let AstNode::BinaryOperation {
            op, left, right, ..
        } = iterable
        {
            if op == ".." {
                let start = self.visit(left, env).int;
                let end = self.visit(right, env).int;
                if let (Some(start), Some(end)) = (start, end) {
                    let count = end.saturating_sub(start);
                    if count >= 0
                        && usize::try_from(count).is_ok_and(|n| n <= MAX_STATIC_LOOP_ITERATIONS)
                    {
                        for value in start..end {
                            if let Some(variable) = variables.first() {
                                env.insert(variable.as_str(), AbstractValue::int(value));
                            }
                            self.visit(body, env);
                            self.merge_continues(env);
                            match self.control {
                                Control::Return => return,
                                Control::Break => {
                                    self.control = Control::Next;
                                    return;
                                }
                                Control::Continue => self.control = Control::Next,
                                Control::Next => {}
                            }
                        }
                        return;
                    }
                }
            }
        }

        // Enumerate known lists; otherwise join all possible backedges.
        let iterable_value = self.visit(iterable, env);
        if let Some(Aggregate::List(values)) = iterable_value
            .aggregate
            .filter(|id| !self.uncertain_lengths.contains(id))
            .and_then(|id| self.heap.get(id))
            .cloned()
        {
            for value in values {
                if let Some(variable) = variables.first() {
                    env.insert(variable.as_str(), value);
                }
                self.visit(body, env);
                self.merge_continues(env);
                match self.control {
                    Control::Return => return,
                    Control::Break => {
                        self.control = Control::Next;
                        return;
                    }
                    Control::Continue => self.control = Control::Next,
                    Control::Next => {}
                }
            }
            return;
        }
        let element = if let Some(Aggregate::List(values)) = iterable_value
            .aggregate
            .and_then(|id| self.heap.get(id))
            .cloned()
        {
            values
                .into_iter()
                .reduce(|a, b| self.join_value(a, b))
                .unwrap_or_default()
        } else {
            AbstractValue {
                aggregate: None,
                list_depth: iterable_value.list_depth.saturating_sub(1),
                list_len: None,
                opaque: iterable_value.opaque || iterable_value.aggregate.is_some(),
                ..iterable_value
            }
        };
        let setup = variables
            .iter()
            .map(|name| (name.as_str(), element))
            .collect::<Vec<_>>();
        self.visit_dynamic_loop(body, env, &setup, None, iterable.location());
    }

    fn visit_while(&mut self, condition: &'a AstNode, body: &'a AstNode, env: &mut Env<'a>) {
        let invariants = loop_integer_invariants(condition, body, env);
        let saved = std::mem::replace(&mut self.integer_invariants, invariants);
        self.loops.push(LoopFrame::default());
        self.visit_while_inner(condition, body, env);
        self.finish_loop(env);
        self.integer_invariants = saved;
    }

    fn visit_while_inner(&mut self, condition: &'a AstNode, body: &'a AstNode, env: &mut Env<'a>) {
        for _ in 0..MAX_STATIC_LOOP_ITERATIONS {
            match self.visit(condition, env).int {
                Some(0) => return,
                Some(_) => {
                    let returns_before = self.returns.len();
                    self.visit(body, env);
                    self.merge_continues(env);
                    let always_true = matches!(
                        condition,
                        AstNode::Literal {
                            value: Value::Bool(true),
                            ..
                        }
                    );
                    if self.needs_output_shapes
                        && self.control == Control::Next
                        && (self.returns.len() > returns_before
                            || (always_true
                                && self
                                    .loops
                                    .last()
                                    .is_some_and(|frame| !frame.breaks.is_empty())))
                    {
                        // A retry path and a return path coexist. Interpret the
                        // remaining backedges abstractly instead of retrying a
                        // runtime-random condition a million times.
                        self.visit_dynamic_loop(
                            body,
                            env,
                            &[],
                            Some(condition),
                            condition.location(),
                        );
                        self.control = if always_true {
                            Control::Return
                        } else {
                            Control::Next
                        };
                        return;
                    }
                    match self.control {
                        Control::Return => return,
                        Control::Break => {
                            self.control = Control::Next;
                            return;
                        }
                        Control::Continue => self.control = Control::Next,
                        Control::Next => {}
                    }
                }
                None => {
                    let mut setup = Vec::new();
                    // Runtime client counters represent a range of slots, not
                    // a literal first slot in the manifest.
                    // The recognized condition only reads two identifiers, so
                    // its evaluation cannot change the counter environment.
                    if let Some((counter, first_client_slot)) =
                        dynamic_client_loop_counter(condition, env)
                    {
                        setup.push((
                            counter,
                            AbstractValue {
                                dynamic_client_slot_start: Some(first_client_slot),
                                ..AbstractValue::default()
                            },
                        ));
                    } else if let AstNode::BinaryOperation { left, right, .. } = condition {
                        for operand in [left, right] {
                            if let AstNode::Identifier(name, _) = operand.as_ref() {
                                let mut value = env.get(name.as_str()).copied().unwrap_or_default();
                                value.int = None;
                                setup.push((name.as_str(), value));
                            }
                        }
                    }
                    self.visit_dynamic_loop(
                        body,
                        env,
                        &setup,
                        Some(condition),
                        condition.location(),
                    );
                    return;
                }
            }
        }
        if self.needs_output_shapes {
            self.errors.push(
                CompilerError::type_error(
                    "Cannot prove share domains across this loop",
                    condition.location(),
                )
                .with_hint("The loop exceeded the static iteration limit"),
            );
        }
    }
}

impl<'a> Planner<'a> {
    /// Join the zero-iteration path and every reachable backedge until the
    /// abstract state stabilizes. A single body visit misses delayed domain
    /// changes (for example `result = previous; previous = new_domain`).
    fn visit_dynamic_loop(
        &mut self,
        body: &'a AstNode,
        env: &mut Env<'a>,
        setup: &[(&'a str, AbstractValue)],
        condition: Option<&'a AstNode>,
        location: SourceLocation,
    ) {
        let counts_before = self.output_counts.clone();
        let initial = self.loop_snapshot(env);
        let returns_before = self.returns.len();
        for iteration in 0..64 {
            for (name, value) in setup {
                env.insert(name, *value);
            }
            let header = self.loop_snapshot(env);
            let uncertain_before = self.uncertain_lengths.clone();
            self.control = Control::Next;
            if iteration > 0 {
                if let Some(condition) = condition {
                    self.visit(condition, env);
                }
            }
            self.visit(body, env);
            self.merge_continues(env);
            let backedge = matches!(self.control, Control::Next | Control::Continue);
            if self.output_counts != counts_before {
                self.errors.push(CompilerError::type_error(
                    "Cannot infer the client-output count of a runtime-bounded loop", location,
                ).with_hint("Use a statically bounded output loop so the client manifest describes the complete batch"));
                self.control = Control::Next;
                return;
            }
            self.merge_loop_state(env, &header.env, &header.heap);
            self.output_offsets = merge_offsets(&header.offsets, &self.output_offsets);
            self.control = Control::Next;
            if !self.needs_output_shapes
                || !backedge
                || (*env == header.env
                    && self.heap == header.heap
                    && self.uncertain_lengths == uncertain_before)
            {
                return;
            }
        }
        // Growing runtime collections need not prevent unrelated code from
        // compiling. Widen changing facts to unknown; any output that depends
        // on them will receive the normal domain/length diagnostic at its use.
        let unknown = AbstractValue {
            opaque: true,
            ..AbstractValue::default()
        };
        for id in initial.env.changed_slots(env) {
            if let Some(value) = env.get_slot_mut(id) {
                *value = unknown;
            }
        }
        for (id, value) in self.heap.iter_mut().enumerate() {
            if initial.heap.get(id) != Some(value) {
                *value = Aggregate::Unknown;
                self.uncertain_lengths.insert(id);
            }
        }
        self.returns[returns_before..].fill(unknown);
    }

    fn loop_snapshot(&self, env: &Env<'a>) -> LoopSnapshot<'a> {
        LoopSnapshot {
            env: env.clone(),
            heap: self.heap.clone(),
            offsets: self.output_offsets.clone(),
        }
    }

    fn merge_snapshot(&mut self, env: &mut Env<'a>, snapshot: LoopSnapshot<'a>) {
        self.merge_loop_state(env, &snapshot.env, &snapshot.heap);
        self.output_offsets = merge_offsets(&self.output_offsets, &snapshot.offsets);
    }

    fn merge_continues(&mut self, env: &mut Env<'a>) {
        let snapshots = self
            .loops
            .last_mut()
            .map(|frame| std::mem::take(&mut frame.continues))
            .unwrap_or_default();
        if self.needs_output_shapes
            && !snapshots.is_empty()
            && matches!(self.control, Control::Return | Control::Break)
        {
            self.control = Control::Next;
        }
        for snapshot in snapshots {
            self.merge_snapshot(env, snapshot);
        }
    }

    fn finish_loop(&mut self, env: &mut Env<'a>) {
        let Some(frame) = self.loops.pop() else {
            return;
        };
        if !frame.breaks.is_empty() {
            self.control = Control::Next;
        }
        for snapshot in frame.breaks.into_iter().chain(frame.continues) {
            self.merge_snapshot(env, snapshot);
        }
    }

    fn referents(&self, id: usize) -> BTreeSet<usize> {
        self.aggregate_aliases
            .get(&id)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([id]))
    }

    fn write_heap(&mut self, id: usize, value: Aggregate) {
        let refs = self.referents(id);
        for referent in &refs {
            let next = if refs.len() == 1 {
                value.clone()
            } else {
                if different_list_lengths(&self.heap[*referent], &value) {
                    self.uncertain_lengths.insert(*referent);
                }
                self.join_aggregate(&self.heap[*referent].clone(), &value)
            };
            self.heap[*referent] = next;
        }
        // Snapshot the affected proxy ids before joining: nested joins may add
        // new aliases. Reverse edges avoid scanning all unrelated alias groups.
        let mut affected: Vec<_> = refs
            .iter()
            .filter_map(|source| self.alias_dependents.get(source))
            .flatten()
            .copied()
            .collect();
        affected.sort_unstable();
        affected.dedup();
        for proxy in affected {
            let sources = &self.aggregate_aliases[&proxy];
            let mut values = sources
                .iter()
                .map(|source| self.heap[*source].clone())
                .collect::<Vec<_>>()
                .into_iter();
            if let Some(mut joined) = values.next() {
                for value in values {
                    if different_list_lengths(&joined, &value) {
                        self.uncertain_lengths.insert(proxy);
                    }
                    joined = self.join_aggregate(&joined, &value);
                }
                self.heap[proxy] = joined;
            }
        }
    }

    fn list_length(&self, value: AbstractValue) -> Option<usize> {
        if let Some(id) = value.aggregate {
            if self.uncertain_lengths.contains(&id) {
                return None;
            }
            if let Some(Aggregate::List(values)) = self.heap.get(id) {
                return Some(values.len());
            }
        }
        value.list_len
    }

    fn default_value(&mut self, ty: &SymbolType, depth: usize) -> AbstractValue {
        if depth > 64 {
            return AbstractValue {
                opaque: true,
                ..AbstractValue::default()
            };
        }
        match ty.underlying_type() {
            SymbolType::List(_) => self.list(Vec::new()),
            SymbolType::Object(name) | SymbolType::TypeName(name) => {
                if let Some(fields) = self.object_types.get(name).cloned() {
                    let fields = fields
                        .into_iter()
                        .map(|f| {
                            (
                                f.name,
                                self.default_value(
                                    &SymbolType::from_ast(&f.type_annotation),
                                    depth + 1,
                                ),
                            )
                        })
                        .collect();
                    let id = self.heap.len();
                    self.heap.push(Aggregate::Object(fields));
                    AbstractValue {
                        aggregate: Some(id),
                        ..AbstractValue::default()
                    }
                } else {
                    self.typed_value(ty)
                }
            }
            _ => self.typed_value(ty),
        }
    }

    fn merge_loop_state(&mut self, env: &mut Env<'a>, original: &Env<'a>, heap_before: &Heap) {
        for id in heap_before.changed_ids(&self.heap) {
            let before = &heap_before[id];
            if different_list_lengths(before, &self.heap[id]) {
                self.uncertain_lengths.insert(id);
            }
            self.heap[id] = self.join_aggregate(before, &self.heap[id].clone());
        }
        for id in original.changed_slots(env) {
            let before = original.get_slot(id).copied().unwrap_or_default();
            let after = env.get_slot(id).copied().unwrap_or_default();
            env.set_slot(id, Some(self.join_value(before, after)));
        }
    }

    fn list(&mut self, values: Vec<AbstractValue>) -> AbstractValue {
        let len = values.len();
        let list_depth = 1 + values.iter().map(|v| v.list_depth).max().unwrap_or(0);
        let id = self.heap.len();
        self.heap.push(Aggregate::List(values));
        AbstractValue {
            aggregate: Some(id),
            list_depth,
            ..AbstractValue::list(len)
        }
    }

    fn apply_type(&mut self, mut value: AbstractValue, ty: &SymbolType) -> AbstractValue {
        match ty.underlying_type() {
            SymbolType::List(inner) => {
                if let Some(id) = value.aggregate {
                    if let Some(Aggregate::List(elements)) = self.heap.get(id).cloned() {
                        let elements = elements
                            .into_iter()
                            .map(|v| self.apply_type(v, inner))
                            .collect();
                        self.heap[id] = Aggregate::List(elements);
                    }
                }
                let typed = self.typed_value(inner);
                value.list_depth = typed.list_depth + 1;
                if !value.opaque {
                    value.share = value.share.or(typed.share);
                }
                value.opaque |= typed.opaque;
            }
            _ => {
                let typed = self.typed_value(ty);
                if !value.opaque {
                    value.share = value.share.or(typed.share);
                }
                value.opaque |= typed.opaque;
                value.float |= typed.float;
            }
        }
        value
    }

    fn typed_value(&self, ty: &SymbolType) -> AbstractValue {
        match ty.underlying_type() {
            SymbolType::List(inner) => {
                let mut value = self.typed_value(inner);
                value.list_depth += 1;
                value
            }
            _ => AbstractValue {
                opaque: matches!(ty.underlying_type(), SymbolType::Object(n) | SymbolType::TypeName(n) if n == "Share"),
                float: !ty.is_secret()
                    && matches!(ty, SymbolType::Float | SymbolType::Fixed { .. }),
                share: crate::codegen::share_type_for_secret_scalar_symbol_type(ty),
                ..AbstractValue::default()
            },
        }
    }

    fn join_value(&mut self, a: AbstractValue, b: AbstractValue) -> AbstractValue {
        if a == b {
            return a;
        }
        let aggregate = match (a.aggregate, b.aggregate) {
            (Some(a), Some(b)) if a == b => Some(a),
            (Some(a), Some(b)) => {
                let value = self.join_aggregate(&self.heap[a].clone(), &self.heap[b].clone());
                let id = self.heap.len();
                if self.uncertain_lengths.contains(&a)
                    || self.uncertain_lengths.contains(&b)
                    || different_list_lengths(&self.heap[a], &self.heap[b])
                {
                    self.uncertain_lengths.insert(id);
                }
                self.heap.push(value);
                let mut refs = self.referents(a);
                refs.extend(self.referents(b));
                for &source in &refs {
                    self.alias_dependents.entry(source).or_default().push(id);
                }
                self.aggregate_aliases.insert(id, refs);
                Some(id)
            }
            _ => None,
        };
        AbstractValue {
            list_depth: a.list_depth.max(b.list_depth),
            opaque: a.opaque || b.opaque || a.share.is_some() || b.share.is_some(),
            float: a.float || b.float,
            share: if a.share == b.share { a.share } else { None },
            aggregate,
            int: if a.int == b.int { a.int } else { None },
            list_len: if a.list_len == b.list_len {
                a.list_len
            } else {
                None
            },
            runtime_client_count: a.runtime_client_count && b.runtime_client_count,
            dynamic_client_slot_start: if a.dynamic_client_slot_start == b.dynamic_client_slot_start
            {
                a.dynamic_client_slot_start
            } else {
                None
            },
        }
    }

    fn join_aggregate(&mut self, a: &Aggregate, b: &Aggregate) -> Aggregate {
        match (a, b) {
            (Aggregate::Closure(a), Aggregate::Closure(b)) if a == b => {
                Aggregate::Closure(a.clone())
            }
            (Aggregate::List(a), Aggregate::List(b)) => Aggregate::List(
                (0..a.len().max(b.len()))
                    .map(|i| {
                        self.join_value(
                            a.get(i).copied().unwrap_or_default(),
                            b.get(i).copied().unwrap_or_default(),
                        )
                    })
                    .collect(),
            ),
            (Aggregate::Object(a), Aggregate::Object(b)) => Aggregate::Object(
                a.keys()
                    .chain(b.keys())
                    .map(|key| {
                        (
                            key.clone(),
                            self.join_value(
                                a.get(key).copied().unwrap_or_default(),
                                b.get(key).copied().unwrap_or_default(),
                            ),
                        )
                    })
                    .collect(),
            ),
            _ => Aggregate::Unknown,
        }
    }

    fn merge_env(&mut self, target: &mut Env<'a>, a: &Env<'a>, b: &Env<'a>) {
        *target = a.clone();
        for id in a.changed_slots(b) {
            let left = a.get_slot(id).copied().unwrap_or_default();
            let right = b.get_slot(id).copied().unwrap_or_default();
            target.set_slot(id, Some(self.join_value(left, right)));
        }
    }

    fn repeat_list(&mut self, list: AbstractValue, count: AbstractValue) -> Option<AbstractValue> {
        let Aggregate::List(values) = self.heap.get(list.aggregate?)?.clone() else {
            return None;
        };
        let count = usize::try_from(count.int?.max(0)).ok()?;
        if values.len().checked_mul(count)? > MAX_STATIC_LOOP_ITERATIONS {
            return None;
        }
        Some(self.list(values.repeat(count)))
    }

    fn assign_aggregate(&mut self, target: &'a AstNode, value: AbstractValue, env: &mut Env<'a>) {
        match target {
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                let object = self.visit(object, env);
                if let Some(Aggregate::Object(fields)) =
                    object.aggregate.and_then(|id| self.heap.get_mut(id))
                {
                    fields.insert(field_name.clone(), value);
                    let id = object.aggregate.unwrap();
                    self.write_heap(id, self.heap[id].clone());
                }
            }
            AstNode::IndexAccess { base, index, .. } => {
                let base = self.visit(base, env);
                let index = self
                    .visit(index, env)
                    .int
                    .and_then(|i| usize::try_from(i).ok());
                // A concrete write with no abstract aliases touches one element.
                // Heap::get_mut preserves branch/backedge snapshots via COW.
                if let (Some(id), Some(index)) = (base.aggregate, index) {
                    if !self.aggregate_aliases.contains_key(&id)
                        && !self.alias_dependents.contains_key(&id)
                    {
                        if let Some(Aggregate::List(values)) = self.heap.get_mut(id) {
                            if let Some(slot) = values.get_mut(index) {
                                *slot = value;
                            }
                            return;
                        }
                    }
                }
                if let Some(Aggregate::List(values)) =
                    base.aggregate.and_then(|id| self.heap.get(id)).cloned()
                {
                    let values = values
                        .into_iter()
                        .enumerate()
                        .map(|(i, old)| {
                            if index == Some(i) {
                                value
                            } else if index.is_none() {
                                self.join_value(old, value)
                            } else {
                                old
                            }
                        })
                        .collect();
                    self.write_heap(base.aggregate.unwrap(), Aggregate::List(values));
                }
            }
            _ => {
                self.visit(target, env);
            }
        }
    }

    fn builtin_value(
        &self,
        name: &str,
        args: &[AbstractValue],
        ty: Option<&SymbolType>,
    ) -> AbstractValue {
        let qualified;
        let name = if !name.contains('.') && args.first().is_some_and(|v| v.share.is_some()) {
            qualified = format!("Share.{name}");
            qualified.as_str()
        } else {
            name
        };
        let width = |index: usize| {
            args.get(index)
                .and_then(|a| a.int)
                .and_then(|n| usize::try_from(n).ok())
        };
        let first = args.first().and_then(|v| v.share);
        let share = match name {
            "Share.from_field" | "Share.random_field" | "Share.add_field" | "Share.mul_field"
            | "add_field" | "mul_field" => Some(ShareType::SecretField),
            "Share.from_clear_int" | "Share.random_int" | "Share.retag" => {
                width(if name == "Share.random_int" { 0 } else { 1 })
                    .and_then(|n| ShareType::try_secret_int(n).ok())
            }
            "Share.from_clear_uint" => width(1).and_then(|n| ShareType::try_secret_uint(n).ok()),
            "Share.from_clear_fixed" => width(1)
                .zip(width(2))
                .and_then(|(k, f)| ShareType::try_secret_fixed_point_from_bits(k, f).ok()),
            "Share.from_clear" => Some(ShareType::default_secret_int()),
            "Share.neg" => first,
            "Share.add_constant" | "Share.add_scalar" | "Share.mul_scalar" => {
                promoted_scalar_domain(first, args.get(1).is_some_and(|v| v.float))
            }
            "Share.add" | "Share.sub" | "Share.mul" => {
                if args.iter().any(|a| a.opaque && a.share.is_none()) {
                    None
                } else {
                    arithmetic_domain("+", first, args.get(1).and_then(|v| v.share))
                }
            }
            "ClientStore.take_share_bool" | "ClientStore.sum_shares_bool" => {
                Some(ShareType::boolean())
            }
            "ClientStore.take_share_fixed" | "ClientStore.sum_shares_fixed" => {
                Some(ShareType::default_secret_fixed_point())
            }
            "ClientStore.take_share" | "ClientStore.sum_shares" | "Share.random" => {
                Some(ShareType::default_secret_int())
            }
            _ => None,
        };
        let typed = ty.map(|ty| self.typed_value(ty)).unwrap_or_default();
        let share = if is_client_input_call(name) || name == "Share.random" {
            typed.share.or(share)
        } else {
            share.or(typed.share.filter(|_| !args.iter().any(|a| a.opaque)))
        };
        AbstractValue { share, ..typed }
    }

    fn record_output_domains(
        &mut self,
        name: &str,
        args: &[AbstractValue],
        location: &SourceLocation,
    ) {
        let (slot, value) = if name == "MpcOutput.send_to_client" {
            (args.first(), args.get(1))
        } else {
            (args.get(1), args.first())
        };
        let Some(slot) = slot.and_then(|a| a.int).and_then(|n| u64::try_from(n).ok()) else {
            return;
        };
        let Some(value) = value else {
            return;
        };
        if value.list_depth > 0
            && (value.aggregate.is_none()
                || value
                    .aggregate
                    .is_some_and(|id| self.uncertain_lengths.contains(&id)))
        {
            self.errors.push(CompilerError::type_error("Cannot infer the number of shares in this client output", location.clone())
                .with_hint("Build the output list with a statically known length, or send known individual shares"));
            return;
        }
        let types = if let Some(Aggregate::List(values)) =
            value.aggregate.and_then(|id| self.heap.get(id))
        {
            values
                .iter()
                .map(|v| if v.list_depth == 0 { v.share } else { None })
                .collect::<Vec<_>>()
        } else {
            vec![value.share]
        };
        self.output_locations.insert(slot, location.clone());
        let offsets = self
            .output_offsets
            .entry(slot)
            .or_insert_with(|| BTreeSet::from([0]));
        let outputs = self.outputs.entry(slot).or_default();
        for start in offsets.iter().copied() {
            for (index, ty) in types.iter().enumerate() {
                let index = start + index;
                if index >= outputs.len() {
                    outputs.resize(index + 1, None);
                    outputs[index] = *ty;
                } else if outputs[index] != *ty {
                    outputs[index] = None;
                }
            }
        }
        *offsets = offsets.iter().map(|offset| offset + types.len()).collect();
    }
}

fn different_list_lengths(a: &Aggregate, b: &Aggregate) -> bool {
    matches!((a, b), (Aggregate::List(a), Aggregate::List(b)) if a.len() != b.len())
}

fn promoted_scalar_domain(share: Option<ShareType>, float: bool) -> Option<ShareType> {
    if !float {
        return share;
    }
    match share {
        Some(ShareType::SecretField) => None,
        Some(ty @ ShareType::SecretFixedPoint { .. }) => Some(ty),
        Some(_) => Some(ShareType::default_secret_fixed_point()),
        None => None,
    }
}

fn arithmetic_domain(op: &str, a: Option<ShareType>, b: Option<ShareType>) -> Option<ShareType> {
    if matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=") && (a.is_some() || b.is_some()) {
        return Some(ShareType::boolean());
    }
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(a), None) | (None, Some(a)) => Some(a),
        // Runtime share/share arithmetic requires matching domains and widths.
        _ => None,
    }
}

fn merge_offsets(
    a: &HashMap<u64, BTreeSet<usize>>,
    b: &HashMap<u64, BTreeSet<usize>>,
) -> HashMap<u64, BTreeSet<usize>> {
    a.keys()
        .chain(b.keys())
        .map(|slot| {
            let zero = BTreeSet::from([0]);
            (
                *slot,
                a.get(slot)
                    .unwrap_or(&zero)
                    .union(b.get(slot).unwrap_or(&zero))
                    .copied()
                    .collect(),
            )
        })
        .collect()
}

fn merge_output_types(a: &InferredOutputs, b: &InferredOutputs) -> InferredOutputs {
    a.keys()
        .chain(b.keys())
        .map(|slot| {
            let a = a.get(slot).map(Vec::as_slice).unwrap_or_default();
            let b = b.get(slot).map(Vec::as_slice).unwrap_or_default();
            let types = (0..a.len().max(b.len()))
                .map(|i| match (a.get(i), b.get(i)) {
                    (Some(a), Some(b)) if a == b => *a,
                    (Some(a), None) | (None, Some(a)) => *a,
                    _ => None,
                })
                .collect();
            (*slot, types)
        })
        .collect()
}

fn dynamic_client_loop_counter<'a>(
    condition: &'a AstNode,
    env: &Env<'_>,
) -> Option<(&'a str, u64)> {
    let AstNode::BinaryOperation {
        op, left, right, ..
    } = condition
    else {
        return None;
    };
    if op != "<" {
        return None;
    }
    let AstNode::Identifier(counter, _) = left.as_ref() else {
        return None;
    };
    let AstNode::Identifier(client_count, _) = right.as_ref() else {
        return None;
    };
    if !env
        .get(client_count.as_str())
        .is_some_and(|value| value.runtime_client_count)
    {
        return None;
    }
    let first_client_slot = env
        .get(counter.as_str())
        .and_then(|value| value.int)
        .and_then(|value| u64::try_from(value).ok())?;
    Some((counter.as_str(), first_client_slot))
}

fn is_list_return_type(node: &AstNode) -> bool {
    match node {
        AstNode::ListType(_) => true,
        AstNode::SecretType(inner) => is_list_return_type(inner),
        _ => false,
    }
}

fn is_client_input_call(name: &str) -> bool {
    matches!(
        name,
        "ClientStore.take_share"
            | "ClientStore.take_share_fixed"
            | "ClientStore.take_share_bool"
            | "ClientStore.sum_shares"
            | "ClientStore.sum_shares_bool"
            | "ClientStore.sum_shares_fixed"
    )
}

fn is_client_input_sum_call(name: &str) -> bool {
    matches!(
        name,
        "ClientStore.sum_shares" | "ClientStore.sum_shares_bool" | "ClientStore.sum_shares_fixed"
    )
}

fn is_client_output_call(name: &str) -> bool {
    matches!(
        name,
        "send_to_client" | "Share.send_to_client" | "MpcOutput.send_to_client"
    )
}

fn eval_binary(op: &str, left: Option<i128>, right: Option<i128>) -> Option<i128> {
    let (left, right) = (left?, right?);
    match op {
        "+" => left.checked_add(right),
        "-" => left.checked_sub(right),
        "*" => left.checked_mul(right),
        "/" => left.checked_div(right),
        "%" => left.checked_rem(right),
        "<<" => u32::try_from(right).ok().and_then(|n| left.checked_shl(n)),
        ">>" => u32::try_from(right).ok().and_then(|n| left.checked_shr(n)),
        "&" => Some(left & right),
        "|" => Some(left | right),
        "^" => Some(left ^ right),
        "==" => Some(i128::from(left == right)),
        "!=" => Some(i128::from(left != right)),
        "<" => Some(i128::from(left < right)),
        "<=" => Some(i128::from(left <= right)),
        ">" => Some(i128::from(left > right)),
        ">=" => Some(i128::from(left >= right)),
        "and" => Some(i128::from(left != 0 && right != 0)),
        "or" => Some(i128::from(left != 0 || right != 0)),
        _ => None,
    }
}

fn merge_branch_output_counts(
    target: &mut HashMap<u64, usize>,
    base: &HashMap<u64, usize>,
    left: &HashMap<u64, usize>,
    right: &HashMap<u64, usize>,
) {
    let slots = base
        .keys()
        .chain(left.keys())
        .chain(right.keys())
        .copied()
        .collect::<HashSet<_>>();
    target.clear();
    for slot in slots {
        let base_count = base.get(&slot).copied().unwrap_or(0);
        let left_delta = left
            .get(&slot)
            .copied()
            .unwrap_or(base_count)
            .saturating_sub(base_count);
        let right_delta = right
            .get(&slot)
            .copied()
            .unwrap_or(base_count)
            .saturating_sub(base_count);
        let count = base_count.saturating_add(left_delta.max(right_delta));
        if count > 0 {
            target.insert(slot, count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AbstractValue, Aggregate, Planner};
    use crate::compiler::{compile, CompilerOptions};
    use stoffel_vm_types::core_types::ShareType;

    #[test]
    fn unused_entry_tail_preserves_io_and_keeps_output_diagnostics() {
        for call in [
            "read_input()",
            "call_closure(create_closure(\"read_input\"))",
        ] {
            let source = format!("def read_input() -> None:\n  var s = ClientStore.take_share_bool(2, 3)\ndef main() -> int64:\n  {call}\n  var x = 0\n  for i in 0..100:\n    x = x + i\n  return x\n");
            let tokens = crate::lexer::tokenize(&source, "tail.stfl").unwrap();
            let ast =
                crate::ufcs::transform_ufcs(crate::parser::parse(&tokens, "tail.stfl").unwrap());
            for needs_output_shapes in [false, true] {
                let mut full = Planner {
                    needs_output_shapes,
                    ..Planner::default()
                };
                let mut trimmed = Planner {
                    needs_output_shapes,
                    ..Planner::default()
                };
                for planner in [&mut full, &mut trimmed] {
                    super::collect_functions(&ast, &mut planner.functions);
                    planner.relevant.insert("read_input".into());
                }
                full.visit_user_call("main", &[], false);
                trimmed.visit_user_call("main", &[], true);
                assert_eq!(full.inputs[&2].len(), 4);
                assert_eq!(trimmed.inputs, full.inputs);
                assert_eq!(trimmed.output_counts, full.output_counts);
                assert_eq!(trimmed.errors.len(), full.errors.len());
                if needs_output_shapes {
                    assert_eq!(trimmed.steps, full.steps);
                } else {
                    assert!(trimmed.steps < full.steps / 2);
                }
            }
        }
    }

    #[test]
    fn integer_loop_cache_preserves_values_writes_and_budget() {
        use super::{AstNode, Env, LoopFrame, SourceLocation, Value};
        let loc = SourceLocation::default();
        let id = |name: &str| AstNode::Identifier(name.into(), loc.clone());
        let lit = |n| AstNode::Literal {
            value: Value::Int {
                value: n,
                kind: None,
            },
            location: loc.clone(),
        };
        let binary = |op: &str, left, right| AstNode::BinaryOperation {
            op: op.into(),
            left: Box::new(left),
            right: Box::new(right),
            location: loc.clone(),
        };
        let assign = |name: &str, value| AstNode::Assignment {
            target: Box::new(id(name)),
            value: Box::new(value),
            location: loc.clone(),
        };
        for mutate_limit in [false, true] {
            let condition = binary("<", id("i"), binary("*", id("limit"), lit(2)));
            let mut statements = vec![assign("i", binary("+", id("i"), lit(1)))];
            if mutate_limit {
                statements.push(assign("limit", binary("-", id("limit"), lit(1))));
            }
            let body = AstNode::Block(statements);
            for steps in [0, 4_999_990] {
                let mut original = Env::new();
                original.insert("i", AbstractValue::int(0));
                original.insert("limit", AbstractValue::int(2));
                let mut cached_env = original.clone();
                let mut uncached = Planner {
                    steps,
                    ..Planner::default()
                };
                let mut cached = Planner {
                    steps,
                    integer_invariants: super::loop_integer_invariants(
                        &condition,
                        &body,
                        &cached_env,
                    ),
                    ..Planner::default()
                };
                if mutate_limit {
                    assert!(cached.integer_invariants.is_none());
                } else {
                    assert!(cached.integer_invariants.is_some());
                }
                uncached.loops.push(LoopFrame::default());
                cached.loops.push(LoopFrame::default());
                uncached.visit_while_inner(&condition, &body, &mut original);
                cached.visit_while_inner(&condition, &body, &mut cached_env);
                assert_eq!(original, cached_env);
                assert_eq!(uncached.steps, cached.steps);
                assert_eq!(uncached.errors.len(), cached.errors.len());
                assert!(uncached.control == cached.control);
            }
        }
    }

    #[test]
    fn concrete_index_access_preserves_heap_snapshots() {
        use super::{AstNode, Env, SourceLocation, Value};
        for index in [0, 2, 99] {
            let loc = SourceLocation::default();
            let target = AstNode::IndexAccess {
                base: Box::new(AstNode::Identifier("items".into(), loc.clone())),
                index: Box::new(AstNode::Literal {
                    value: Value::Int {
                        value: index,
                        kind: None,
                    },
                    location: loc.clone(),
                }),
                location: loc,
            };
            let mut planner = Planner::default();
            let mut expected = vec![AbstractValue::int(1); 3];
            let list = planner.list(expected.clone());
            let before = planner.heap.clone();
            let mut env = Env::new();
            env.insert("items", list);
            planner.assign_aggregate(&target, AbstractValue::int(7), &mut env);
            if let Some(slot) = expected.get_mut(index as usize) {
                *slot = AbstractValue::int(7);
            }
            assert_eq!(
                planner.visit(&target, &mut env),
                expected.get(index as usize).copied().unwrap_or_default()
            );
            assert_eq!(planner.heap[0], Aggregate::List(expected));
            assert_eq!(before[0], Aggregate::List(vec![AbstractValue::int(1); 3]));
        }
    }

    #[test]
    fn heap_snapshots_preserve_branches_across_page_boundaries() {
        let mut heap = super::Heap::default();
        let mut flat = Vec::new();
        for i in 0..150 {
            let value = Aggregate::List(vec![AbstractValue::int(i)]);
            heap.push(value.clone());
            flat.push(value);
        }
        let before = heap.clone();
        let original = flat.clone();
        for i in [0, 63, 64, 127, 149] {
            heap[i] = Aggregate::Unknown;
            flat[i] = Aggregate::Unknown;
        }
        for i in 0..130 {
            heap.push(Aggregate::Closure(i.to_string()));
            flat.push(Aggregate::Closure(i.to_string()));
        }
        let expected: Vec<_> = original
            .iter()
            .zip(&flat)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(before.changed_ids(&heap), expected);
        heap.restore_prefix(&before);
        flat[..original.len()].clone_from_slice(&original);
        assert_eq!(heap.len(), flat.len());
        for (i, value) in flat.iter().enumerate() {
            assert_eq!(&heap[i], value);
        }
        assert!(before.changed_ids(&heap).is_empty());
        let mut exact = before.clone();
        exact[149] = Aggregate::Unknown;
        exact.restore_prefix(&before);
        assert_eq!(exact, before);
    }

    #[test]
    fn indexed_alias_updates_match_exhaustive_propagation() {
        fn exhaustive_write(planner: &mut Planner<'_>, id: usize, value: Aggregate) {
            let refs = planner.referents(id);
            for &source in &refs {
                let next = if refs.len() == 1 {
                    value.clone()
                } else {
                    if super::different_list_lengths(&planner.heap[source], &value) {
                        planner.uncertain_lengths.insert(source);
                    }
                    planner.join_aggregate(&planner.heap[source].clone(), &value)
                };
                planner.heap[source] = next;
            }
            let mut affected: Vec<_> = planner
                .aggregate_aliases
                .iter()
                .filter(|(_, sources)| !sources.is_disjoint(&refs))
                .map(|(&id, sources)| (id, sources.clone()))
                .collect();
            affected.sort_unstable_by_key(|(id, _)| *id);
            for (proxy, sources) in affected {
                let mut values = sources
                    .iter()
                    .map(|&id| planner.heap[id].clone())
                    .collect::<Vec<_>>()
                    .into_iter();
                if let Some(mut joined) = values.next() {
                    for value in values {
                        if super::different_list_lengths(&joined, &value) {
                            planner.uncertain_lengths.insert(proxy);
                        }
                        joined = planner.join_aggregate(&joined, &value);
                    }
                    planner.heap[proxy] = joined;
                }
            }
        }
        let mut planner = Planner::default();
        let mut values: Vec<_> = (0..8)
            .map(|i| planner.list(vec![AbstractValue::int(i)]))
            .collect();
        for i in 0..7 {
            values.push(planner.join_value(values[i], values[i + 1]));
        }
        let left = planner.list(values[..4].to_vec());
        let right = planner.list(values[4..8].to_vec());
        values.push(left);
        values.push(right);
        values.push(planner.join_value(left, right));
        let mut reference = Planner {
            heap: planner.heap.clone(),
            aggregate_aliases: planner.aggregate_aliases.clone(),
            alias_dependents: planner.alias_dependents.clone(),
            uncertain_lengths: planner.uncertain_lengths.clone(),
            ..Planner::default()
        };
        for step in 0..80 {
            let id = values[(step * 7) % values.len()].aggregate.unwrap();
            let value = Aggregate::List(vec![AbstractValue::int(step as i128 % 3); step % 4]);
            exhaustive_write(&mut reference, id, value.clone());
            planner.write_heap(id, value);
            assert_eq!(planner.heap, reference.heap, "write {step}");
            assert_eq!(planner.aggregate_aliases, reference.aggregate_aliases);
            assert_eq!(planner.uncertain_lengths, reference.uncertain_lengths);
        }
    }

    #[test]
    fn writes_refresh_merged_aliases_without_changing_unrelated_lists() {
        let mut planner = Planner::default();
        let value = AbstractValue::int;
        let a = planner.list(vec![value(1)]);
        let b = planner.list(vec![value(1)]);
        let merged = planner.join_value(a, b).aggregate.unwrap();
        let c = planner.list(vec![value(4)]);
        let d = planner.list(vec![value(4)]);
        let unrelated = planner.join_value(c, d).aggregate.unwrap();
        let original = planner.heap[unrelated].clone();

        planner.write_heap(a.aggregate.unwrap(), Aggregate::List(vec![value(2)]));
        let Aggregate::List(values) = &planner.heap[merged] else {
            panic!("expected merged list")
        };
        assert_eq!(values[0].int, None, "the other referent still contains one");
        planner.write_heap(b.aggregate.unwrap(), Aggregate::List(vec![value(2)]));
        let Aggregate::List(values) = &planner.heap[merged] else {
            panic!("expected merged list")
        };
        assert_eq!(values[0].int, Some(2), "both referents now agree");
        assert_eq!(planner.heap[unrelated], original);

        planner.write_heap(merged, Aggregate::List(vec![value(3)]));
        for id in [a.aggregate.unwrap(), b.aggregate.unwrap(), merged] {
            let Aggregate::List(values) = &planner.heap[id] else {
                panic!("expected aliased list")
            };
            assert_eq!(
                values[0].int, None,
                "a merged reference requires weak updates"
            );
        }
        assert_eq!(planner.heap[unrelated], original);
    }

    #[test]
    fn programs_without_client_io_do_not_execute_the_planner() {
        let tokens = crate::lexer::tokenize(
            "def main() -> int64:\n  var x = 0\n  for i in 0..1000000:\n    x += i\n  return x\n",
            "no_io.stfl",
        )
        .unwrap();
        let ast = crate::parser::parse(&tokens, "no_io.stfl").unwrap();
        for output_shapes in [false, true] {
            let planner = super::plan_client_io(&ast, &[], output_shapes);
            assert_eq!(planner.steps, 0);
            assert!(planner.inputs.is_empty());
            assert!(planner.outputs.is_empty());
        }
    }

    #[test]
    fn client_io_fast_path_preserves_top_level_and_extra_entry_outputs() {
        for source in [
            "var x = ClientStore.take_share_bool(2, 0)\nx.send_to_client(2)\n",
            "def helper() -> None:\n  var x = ClientStore.take_share_bool(2, 0)\n  x.send_to_client(2)\ndef main() -> None:\n  helper()\n",
            "def other() -> None:\n  var x = ClientStore.take_share_bool(2, 0)\n  x.send_to_client(2)\ndef main() -> int64:\n  return 0\n",
        ] {
            for level in 0..=3 {
                let options = CompilerOptions {
                    optimize: level > 0,
                    optimization_level: level,
                    entry_points: vec!["other".to_string()],
                    ..Default::default()
                };
                let program = compile(source, "io.stfl", &options).unwrap();
                let schema = program.client_io_manifest.clients.iter()
                    .find(|schema| schema.client_slot == 2).unwrap();
                assert_eq!(schema.inputs.len(), 1);
                assert_eq!(schema.outputs.len(), 1);
                assert_eq!(schema.inputs, schema.outputs);
            }
        }
    }

    #[test]
    fn follows_literal_integer_arguments_through_nested_client_input_helpers() {
        let source = r#"
def take_byte(client: int64, byte_index: int64) -> list[secret bool]:
  var bits: list[secret bool] = []
  for bit_index in 0..8:
    bits.append(ClientStore.take_share_bool(client, byte_index * 8 + bit_index))
  return bits

def take_block(client: int64, block_index: int64) -> list[list[secret bool]]:
  var block: list[list[secret bool]] = []
  for byte_index in 0..2:
    block.append(take_byte(client, block_index * 2 + byte_index))
  return block

def main() -> int64:
  var left = take_block(0, 0)
  var right = take_block(1, 0)
  return 0
"#;
        let program = compile(source, "client_helpers.stfl", &CompilerOptions::default())
            .expect("program should compile");
        assert_eq!(program.client_io_manifest.clients.len(), 2);
        for schema in &program.client_io_manifest.clients {
            assert_eq!(schema.inputs, vec![ShareType::boolean(); 16]);
        }
    }

    #[test]
    fn executes_clear_bounded_while_loops_in_client_input_helpers() {
        let source = r#"
def take_values(client: int64, width: int64) -> list[secret fix64]:
  var values: list[secret fix64] = []
  var i: int64 = 0
  while i < width:
    values.append(ClientStore.take_share_fixed(client, i))
    i += 1
  return values

def main() -> int64:
  var values = take_values(2, 4)
  return 0
"#;
        let program = compile(source, "client_while.stfl", &CompilerOptions::default())
            .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.client_slot, 2);
        assert_eq!(
            schema.inputs,
            vec![ShareType::default_secret_fixed_point(); 4]
        );
    }

    #[test]
    fn plain_take_share_does_not_erase_an_explicit_boolean_annotation() {
        let source = r#"
def main() -> int64:
  var bits: list[secret bool] = []
  var i: int64 = 0
  while i < 4:
    var bit: secret bool = ClientStore.take_share(0, i)
    bits.append(bit)
    i += 1
  return 0
"#;
        let program = compile(
            source,
            "annotated_bool_inputs.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.client_slot, 0);
        assert_eq!(schema.inputs, vec![ShareType::boolean(); 4]);
    }

    #[test]
    fn dynamic_client_loop_records_a_runtime_input_template_without_inventing_a_slot() {
        let source = r#"
def main() -> int64:
  var clients = ClientStore.get_number_clients()
  var client = 1
  while client < clients:
    discard ClientStore.take_share_fixed(client, 0)
    client += 1
  discard ClientStore.take_share_fixed(0, 0)
  return 0
"#;
        let program = compile(source, "dynamic_clients.stfl", &CompilerOptions::default())
            .expect("program should compile");
        assert_eq!(program.client_io_manifest.clients.len(), 1);
        assert_eq!(program.client_io_manifest.clients[0].client_slot, 0);
        assert_eq!(program.client_io_manifest.dynamic_client_inputs.len(), 1);
        assert_eq!(
            program.client_io_manifest.dynamic_client_inputs[0].first_client_slot,
            1
        );
        assert_eq!(
            program.client_io_manifest.dynamic_client_inputs[0].inputs,
            vec![ShareType::default_secret_fixed_point()]
        );
    }

    #[test]
    fn dynamic_client_template_collects_each_statically_bounded_input_ordinal() {
        let source = r#"
def main() -> int64:
  var clients = ClientStore.get_number_clients()
  var ordinal = 0
  while ordinal < 4:
    var client = 0
    while client < clients:
      discard ClientStore.take_share_fixed(client, ordinal)
      client += 1
    ordinal += 1
  return 0
"#;
        let program = compile(
            source,
            "dynamic_client_inputs.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        assert!(program.client_io_manifest.clients.is_empty());
        assert_eq!(program.client_io_manifest.dynamic_client_inputs.len(), 1);
        let schema = &program.client_io_manifest.dynamic_client_inputs[0];
        assert_eq!(schema.first_client_slot, 0);
        assert_eq!(
            schema.inputs,
            vec![ShareType::default_secret_fixed_point(); 4]
        );
    }

    #[test]
    fn bounded_output_loop_records_every_output_share() {
        let source = r#"
def main() -> None:
  var value: secret int64 = Share.from_clear_int(7, 64)
  var i: int64 = 0
  while i < 4:
    value.send_to_client(0)
    i += 1
"#;
        let program = compile(
            source,
            "looped_client_outputs.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.client_slot, 0);
        assert_eq!(schema.outputs, vec![ShareType::default_secret_int(); 4]);
    }

    #[test]
    fn output_loop_uses_length_of_append_built_list() {
        let source = r#"
def main() -> None:
  var values: list[secret int64] = []
  var i: int64 = 0
  while i < 8:
    values.append(ClientStore.take_share(0, i))
    i += 1
  for j in 0..values.len():
    values[j].send_to_client(0)
"#;
        let program = compile(source, "list_output_loop.stfl", &CompilerOptions::default())
            .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.inputs.len(), 8);
        assert_eq!(schema.outputs.len(), 8);
    }

    #[test]
    fn output_loop_uses_length_returned_by_list_building_helper() {
        let source = r#"
def histogram(bounds: list[int64]) -> list[Share]:
  var out: list[Share] = []
  var b = 0
  while b < (len(bounds) - 1):
    out.append(Share.from_clear_int(b, 64))
    b += 1
  return out

def main() -> None:
  var h = histogram([0, 10, 20, 30])
  var client = 0
  while client < 5:
    var b = 0
    while b < len(h):
      h[b].send_to_client(client)
      b += 1
    client += 1
"#;
        let program = compile(
            source,
            "helper_list_output_loop.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        assert_eq!(program.client_io_manifest.clients.len(), 5);
        for (client_slot, schema) in program.client_io_manifest.clients.iter().enumerate() {
            assert_eq!(schema.client_slot, client_slot as u64);
            assert_eq!(schema.outputs.len(), 3);
        }
    }
}
