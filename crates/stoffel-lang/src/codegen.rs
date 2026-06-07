use crate::ast::{AstNode, Pragma};
use crate::bytecode::{BytecodeChunk, CompiledProgram, Constant, Instruction};
use crate::errors::{CompilerError, CompilerResult};
use crate::register_allocator::{self, AllocationError, PhysicalRegister, VirtualRegister};
use crate::symbol_table::SymbolType;
use stoffel_vm_types::compiled_binary::{ClientIoManifest, ClientIoSchema, MpcBackend};
use stoffel_vm_types::core_types::ShareType;
use stoffel_vm_types::registers::DEFAULT_SECRET_REGISTER_START;

use std::collections::HashMap;
use std::collections::HashSet;
const SECRET_REGISTER_START: usize = DEFAULT_SECRET_REGISTER_START;
const MAX_REGISTERS: usize = SECRET_REGISTER_START * 2;

/// It receives the generator state, the function definition node, and the pragma node.
type PragmaHandler = fn(&mut CodeGenerator, &AstNode, &Pragma) -> CompilerResult<()>;

fn int_literal_u64(node: Option<&AstNode>) -> Option<u64> {
    match node {
        Some(AstNode::Literal {
            value: crate::ast::Value::Int { value, .. },
            ..
        }) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn infer_single_share_type(node: &AstNode) -> Option<ShareType> {
    match node {
        AstNode::FunctionCall { function, .. } => match function.as_ref() {
            AstNode::Identifier(name, _) if name == "ClientStore.take_share_fixed" => {
                Some(ShareType::default_secret_fixed_point())
            }
            AstNode::Identifier(name, _) if name == "ClientStore.take_share" => {
                Some(ShareType::default_secret_int())
            }
            AstNode::Identifier(name, _) if name.ends_with("from_clear_fixed") => {
                Some(ShareType::default_secret_fixed_point())
            }
            AstNode::Identifier(name, _) if name.ends_with("from_clear_int") => {
                Some(ShareType::default_secret_int())
            }
            _ => None,
        },
        _ => None,
    }
}

fn share_type_for_secret_scalar_symbol_type(ty: &SymbolType) -> Option<ShareType> {
    if !ty.is_secret() {
        return None;
    }
    if ty.underlying_type() == &SymbolType::Bool {
        return Some(ShareType::boolean());
    }
    ty.bit_width()
        .map(|bit_width| ShareType::secret_int(usize::from(bit_width)))
}

fn is_share_random_call(function: &AstNode) -> bool {
    matches!(function, AstNode::Identifier(name, _) if name == "Share.random")
}

#[derive(Debug)]
struct CodeGenerator {
    // Holds instructions using VirtualRegisters during generation for a scope.
    current_instructions: Vec<Instruction>,
    // Holds labels mapped to their *virtual* instruction index.
    current_labels: HashMap<String, usize>,
    // Counter for allocating new virtual registers.
    next_virtual_reg: usize,
    // Tracks the required secrecy for each virtual register. True = Secret.
    vr_secrecy: HashMap<VirtualRegister, bool>,
    // Variable symbol table (maps name to VirtualRegister index). Local to the current scope.
    symbol_table: HashMap<String, usize>,
    // Source-level types for variables in this scope.
    symbol_types: HashMap<String, SymbolType>,
    // User object fields available for default construction in this scope.
    object_field_types: HashMap<String, Vec<(String, SymbolType)>>,
    // Compiled functions.
    compiled_functions: HashMap<String, BytecodeChunk>,
    // If present, this chunk represents `def main(...)` promoted to the program entry.
    main_proc_chunk: Option<BytecodeChunk>,
    // If present, this chunk represents a pragma-marked entry function.
    entry_main_chunk: Option<BytecodeChunk>,
    // Known built-in functions (names only, no bytecode generated).
    known_builtins: HashSet<String>,
    // Pragma handlers: Maps pragma names to their handler functions.
    pragma_handlers: HashMap<String, PragmaHandler>,
    // Constants identified during code generation for this chunk.
    identified_constants: Vec<Constant>,
    client_inputs: HashMap<u64, Vec<Option<ShareType>>>,
    client_outputs: HashMap<u64, Vec<ShareType>>,
    variable_share_types: HashMap<String, ShareType>,
    variable_share_lists: HashMap<String, Vec<ShareType>>,
    clear_int_constants: HashMap<String, u64>,
    active_loop_bounds: Vec<(String, u64)>,
}

impl CodeGenerator {
    fn new() -> Self {
        let known_builtins = crate::builtin_registry::builtin_registry().known_call_names();

        CodeGenerator {
            current_instructions: Vec::new(),
            current_labels: HashMap::new(),
            next_virtual_reg: 0, // Start virtual registers from 0
            vr_secrecy: HashMap::new(),
            // Symbol table starts empty for each new generator instance (e.g., per function)
            symbol_table: HashMap::new(),
            symbol_types: HashMap::new(),
            object_field_types: HashMap::new(),
            compiled_functions: HashMap::new(),
            main_proc_chunk: None,
            entry_main_chunk: None,
            known_builtins,
            pragma_handlers: Self::register_pragma_handlers(),
            identified_constants: Vec::new(),
            client_inputs: HashMap::new(),
            client_outputs: HashMap::new(),
            variable_share_types: HashMap::new(),
            variable_share_lists: HashMap::new(),
            clear_int_constants: HashMap::new(),
            active_loop_bounds: Vec::new(),
        }
    }

    /// Registers built-in pragma handlers.
    fn register_pragma_handlers() -> HashMap<String, PragmaHandler> {
        let mut handlers: HashMap<String, PragmaHandler> = HashMap::new();

        // Register the "builtin" pragma handler
        handlers.insert("builtin".to_string(), handle_builtin_pragma);

        handlers
    }

    /// Allocates a new unique virtual register.
    /// Records whether the register needs to hold a secret value.
    fn allocate_virtual_register(&mut self, is_secret: bool) -> VirtualRegister {
        let vr = VirtualRegister(self.next_virtual_reg);
        self.next_virtual_reg += 1;
        self.vr_secrecy.insert(vr, is_secret);
        vr
    }

    fn emit_unit_value(&mut self) -> (VirtualRegister, bool) {
        let vr = self.allocate_virtual_register(false);
        self.identified_constants.push(Constant::Unit);
        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
        (vr, false)
    }

    fn compile_default_value_for_type(
        &mut self,
        ty: &SymbolType,
        is_secret_register: bool,
    ) -> CompilerResult<(VirtualRegister, bool)> {
        if let Some(object_name) = self.default_object_type_name(ty) {
            self.emit(Instruction::CALL("create_object".to_string()));
            let object_vr = self.allocate_virtual_register(false);
            self.emit(Instruction::MOV(object_vr.0, 0));

            if let Some(fields) = self.object_field_types.get(&object_name).cloned() {
                for (field_name, field_type) in fields {
                    if let Some((field_vr, _)) =
                        self.compile_default_field_value_for_type(&field_type)?
                    {
                        let field_const = Constant::String(field_name);
                        self.identified_constants.push(field_const.clone());
                        let field_name_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::LDI(
                            field_name_vr.0,
                            crate::core_types::Value::from(field_const),
                        ));

                        self.emit(Instruction::PUSHARG(object_vr.0));
                        self.emit(Instruction::PUSHARG(field_name_vr.0));
                        self.emit(Instruction::PUSHARG(field_vr.0));
                        self.emit(Instruction::CALL("set_field".to_string()));
                    }
                }
            }

            Ok((object_vr, false))
        } else {
            match ty.underlying_type() {
                SymbolType::List(_) => {
                    self.emit(Instruction::CALL("create_array".to_string()));
                    let array_vr = self.allocate_virtual_register(false);
                    self.emit(Instruction::MOV(array_vr.0, 0));
                    Ok((array_vr, false))
                }
                _ => {
                    if is_secret_register {
                        let clear_constant = match ty.underlying_type() {
                            SymbolType::Float => Constant::Float(crate::bytecode::F64::new(0.0)),
                            SymbolType::Bool => Constant::Bool(false),
                            ty if ty.is_integer() => Constant::I64(0),
                            _ => Constant::Unit,
                        };
                        let clear_vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(clear_constant.clone());
                        self.emit(Instruction::LDI(
                            clear_vr.0,
                            crate::core_types::Value::from(clear_constant),
                        ));
                        let secret_vr = self.allocate_virtual_register(true);
                        self.emit(Instruction::MOV(secret_vr.0, clear_vr.0));
                        Ok((secret_vr, true))
                    } else {
                        let vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::Unit);
                        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
                        Ok((vr, false))
                    }
                }
            }
        }
    }

    fn compile_default_field_value_for_type(
        &mut self,
        ty: &SymbolType,
    ) -> CompilerResult<Option<(VirtualRegister, bool)>> {
        match ty.underlying_type() {
            SymbolType::List(_) => self.compile_default_value_for_type(ty, false).map(Some),
            _ if self.default_object_type_name(ty).is_some() => {
                self.compile_default_value_for_type(ty, false).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn default_object_type_name(&self, ty: &SymbolType) -> Option<String> {
        match ty.underlying_type() {
            SymbolType::Object(name) | SymbolType::TypeName(name)
                if self.object_field_types.contains_key(name) =>
            {
                Some(name.clone())
            }
            _ => None,
        }
    }

    /// Adds an instruction to the current temporary list.
    fn emit(&mut self, instruction: Instruction) {
        self.current_instructions.push(instruction);
    }

    fn record_client_io_call(&mut self, function_name: &str, arguments: &[AstNode]) {
        match function_name {
            "ClientStore.take_share" | "ClientStore.take_share_fixed" => {
                let Some(client_slot) = int_literal_u64(arguments.first()) else {
                    return;
                };
                let Some(input_ordinals) = self.input_ordinals_for_node(arguments.get(1)) else {
                    return;
                };
                let share_type = if function_name == "ClientStore.take_share_fixed" {
                    ShareType::default_secret_fixed_point()
                } else {
                    ShareType::default_secret_int()
                };
                let inputs = self.client_inputs.entry(client_slot).or_default();
                for input_ordinal in input_ordinals {
                    let ordinal = input_ordinal as usize;
                    if inputs.len() <= ordinal {
                        inputs.resize(ordinal + 1, None);
                    }
                    inputs[ordinal] = Some(share_type);
                }
            }
            "MpcOutput.send_to_client" => {
                let Some(client_slot) = int_literal_u64(arguments.first()) else {
                    return;
                };
                if let Some(value) = arguments.get(1) {
                    let outputs = self.output_share_types_for_node(value);
                    self.client_outputs
                        .entry(client_slot)
                        .or_default()
                        .extend(outputs);
                }
            }
            "send_to_client" => {
                let Some(client_slot) = int_literal_u64(arguments.get(1)) else {
                    return;
                };
                let share_type = arguments
                    .first()
                    .and_then(|argument| self.share_type_for_node(argument))
                    .unwrap_or_else(ShareType::default_secret_int);
                self.client_outputs
                    .entry(client_slot)
                    .or_default()
                    .push(share_type);
            }
            _ => {}
        }
    }

    fn record_share_list_append_call(&mut self, function_name: &str, arguments: &[AstNode]) {
        if function_name != "append" && function_name != "array_push" {
            return;
        }
        let Some(AstNode::Identifier(list_name, _)) = arguments.first() else {
            return;
        };
        let Some(share_type) = arguments
            .get(1)
            .and_then(|argument| self.share_type_for_node(argument))
        else {
            return;
        };
        let repeat = self.active_loop_iteration_count();
        self.variable_share_lists
            .entry(list_name.clone())
            .or_default()
            .extend(std::iter::repeat_n(share_type, repeat));
    }

    fn input_ordinals_for_node(&self, node: Option<&AstNode>) -> Option<Vec<u64>> {
        match node? {
            AstNode::Literal { .. } => int_literal_u64(node).map(|ordinal| vec![ordinal]),
            AstNode::Identifier(name, _) => {
                self.active_loop_bounds
                    .iter()
                    .rev()
                    .find_map(|(loop_var, bound)| {
                        (loop_var == name).then(|| (0..*bound).collect::<Vec<_>>())
                    })
            }
            _ => None,
        }
    }

    fn loop_bound_for_condition(&self, condition: &AstNode) -> Option<(String, u64)> {
        let AstNode::BinaryOperation {
            op, left, right, ..
        } = condition
        else {
            return None;
        };
        if op != "<" {
            return None;
        }
        let AstNode::Identifier(loop_var, _) = left.as_ref() else {
            return None;
        };
        let bound = int_literal_u64(Some(right.as_ref())).or_else(|| match right.as_ref() {
            AstNode::Identifier(name, _) => self.clear_int_constants.get(name).copied(),
            _ => None,
        })?;
        Some((loop_var.clone(), bound))
    }

    fn active_loop_iteration_count(&self) -> usize {
        self.active_loop_bounds
            .iter()
            .map(|(_, bound)| usize::try_from(*bound).unwrap_or(usize::MAX))
            .fold(1_usize, usize::saturating_mul)
    }

    fn share_type_for_node(&self, node: &AstNode) -> Option<ShareType> {
        match node {
            AstNode::Identifier(name, _) => self.variable_share_types.get(name).copied(),
            AstNode::FunctionCall {
                resolved_return_type,
                ..
            } => resolved_return_type
                .as_ref()
                .and_then(share_type_for_secret_scalar_symbol_type)
                .or_else(|| infer_single_share_type(node)),
            AstNode::BinaryOperation { left, right, .. } => {
                let left = self.share_type_for_node(left);
                let right = self.share_type_for_node(right);
                match (left, right) {
                    (
                        Some(ShareType::SecretFixedPoint { precision }),
                        Some(ShareType::SecretFixedPoint { .. }),
                    )
                    | (
                        Some(ShareType::SecretFixedPoint { precision }),
                        Some(ShareType::SecretInt { .. }),
                    )
                    | (
                        Some(ShareType::SecretInt { .. }),
                        Some(ShareType::SecretFixedPoint { precision }),
                    ) => Some(ShareType::SecretFixedPoint { precision }),
                    (Some(left), _) => Some(left),
                    (_, Some(right)) => Some(right),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn output_share_types_for_node(&self, node: &AstNode) -> Vec<ShareType> {
        match node {
            AstNode::Identifier(name, _) => self
                .variable_share_lists
                .get(name)
                .cloned()
                .or_else(|| {
                    self.variable_share_types
                        .get(name)
                        .copied()
                        .map(|ty| vec![ty])
                })
                .unwrap_or_else(|| vec![ShareType::default_secret_int()]),
            AstNode::ListLiteral { elements, .. } => elements
                .iter()
                .map(|element| {
                    self.share_type_for_node(element)
                        .unwrap_or_else(ShareType::default_secret_int)
                })
                .collect(),
            _ => vec![self
                .share_type_for_node(node)
                .unwrap_or_else(ShareType::default_secret_int)],
        }
    }

    fn client_io_manifest(&self) -> ClientIoManifest {
        let mut slots = self
            .client_inputs
            .keys()
            .chain(self.client_outputs.keys())
            .copied()
            .collect::<Vec<_>>();
        slots.sort_unstable();
        slots.dedup();

        ClientIoManifest {
            mpc_backend: MpcBackend::default(),
            mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::default(),
            clients: slots
                .into_iter()
                .map(|client_slot| {
                    let inputs = self
                        .client_inputs
                        .get(&client_slot)
                        .map(|inputs| {
                            inputs
                                .iter()
                                .map(|share_type| {
                                    share_type.unwrap_or_else(ShareType::default_secret_int)
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let outputs = self
                        .client_outputs
                        .get(&client_slot)
                        .cloned()
                        .unwrap_or_default();
                    ClientIoSchema {
                        client_slot,
                        inputs,
                        outputs,
                    }
                })
                .collect(),
        }
    }

    fn merge_client_io_from(&mut self, other: &CodeGenerator) {
        for (client_slot, inputs) in &other.client_inputs {
            let target = self.client_inputs.entry(*client_slot).or_default();
            if target.len() < inputs.len() {
                target.resize(inputs.len(), None);
            }
            for (idx, share_type) in inputs.iter().enumerate() {
                if share_type.is_some() {
                    target[idx] = *share_type;
                }
            }
        }
        for (client_slot, outputs) in &other.client_outputs {
            self.client_outputs
                .entry(*client_slot)
                .or_default()
                .extend(outputs.iter().copied());
        }
    }

    /// Adds a label pointing to the *next* instruction index.
    fn add_label(&mut self, label: String) {
        let pos = self.current_instructions.len();
        self.current_labels.insert(label, pos);
    }

    fn type_hint_for_node(&self, node: &AstNode) -> Option<SymbolType> {
        match node {
            AstNode::Identifier(name, _) => self.symbol_types.get(name).cloned(),
            AstNode::FieldAccess {
                object, field_name, ..
            } => self
                .type_hint_for_node(object)
                .and_then(|object_type| self.field_type_for_object_type(&object_type, field_name)),
            AstNode::IndexAccess { base, .. } => {
                self.type_hint_for_node(base).and_then(|base_type| {
                    match base_type.underlying_type() {
                        SymbolType::List(element_type) => Some(element_type.as_ref().clone()),
                        SymbolType::String => Some(SymbolType::String),
                        SymbolType::Dict(_, value_type) => Some(value_type.as_ref().clone()),
                        _ => None,
                    }
                })
            }
            AstNode::FunctionCall {
                resolved_return_type,
                ..
            } => resolved_return_type.clone(),
            AstNode::Literal { value, .. } => match value {
                crate::ast::Value::Int { kind, .. } => match kind {
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W8)) => {
                        Some(SymbolType::Int8)
                    }
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W16)) => {
                        Some(SymbolType::Int16)
                    }
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W32)) => {
                        Some(SymbolType::Int32)
                    }
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W64)) => {
                        Some(SymbolType::Int64)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W8)) => {
                        Some(SymbolType::UInt8)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W16)) => {
                        Some(SymbolType::UInt16)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W32)) => {
                        Some(SymbolType::UInt32)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W64)) => {
                        Some(SymbolType::UInt64)
                    }
                    None => Some(SymbolType::Int64),
                },
                crate::ast::Value::Float(_) => Some(SymbolType::Float),
                crate::ast::Value::String(_) => Some(SymbolType::String),
                crate::ast::Value::Bool(_) => Some(SymbolType::Bool),
                crate::ast::Value::Nil => Some(SymbolType::Nil),
            },
            _ => None,
        }
    }

    fn field_type_for_object_type(
        &self,
        object_type: &SymbolType,
        field_name: &str,
    ) -> Option<SymbolType> {
        let object_name = match object_type.underlying_type() {
            SymbolType::Object(name) | SymbolType::TypeName(name) => name,
            _ => return None,
        };
        self.object_field_types.get(object_name).and_then(|fields| {
            fields
                .iter()
                .find_map(|(name, ty)| (name == field_name).then(|| ty.clone()))
        })
    }

    /// Compiles an AST node, returning the VirtualRegister holding the result
    /// and a boolean indicating if the result is secret.
    fn compile_node(&mut self, node: &AstNode) -> CompilerResult<(VirtualRegister, bool)> {
        match node {
            // --- Literals ---
            AstNode::Literal { value: lit, .. } => {
                // Literals are initially clear
                let vr = self.allocate_virtual_register(false); // Literals are clear
                let constant = match lit {
                    crate::ast::Value::Int { value, kind } => {
                        match kind {
                            Some(crate::ast::IntKind::Signed(w)) => match w {
                                crate::ast::IntWidth::W8 => Constant::I8(*value as i8),
                                crate::ast::IntWidth::W16 => Constant::I16(*value as i16),
                                crate::ast::IntWidth::W32 => Constant::I32(*value as i32),
                                crate::ast::IntWidth::W64 => Constant::I64(*value as i64),
                            },
                            Some(crate::ast::IntKind::Unsigned(w)) => match w {
                                crate::ast::IntWidth::W8 => Constant::U8(*value as u8),
                                crate::ast::IntWidth::W16 => Constant::U16(*value as u16),
                                crate::ast::IntWidth::W32 => Constant::U32(*value as u32),
                                crate::ast::IntWidth::W64 => Constant::U64(*value as u64),
                            },
                            None => Constant::I64(*value as i64), // default behavior
                        }
                    }
                    crate::ast::Value::Float(f) => {
                        Constant::Float(crate::bytecode::F64::new(f64::from_bits(*f)))
                    }
                    crate::ast::Value::String(s) => Constant::String(s.clone()),
                    crate::ast::Value::Bool(b) => Constant::Bool(*b),
                    crate::ast::Value::Nil => Constant::Unit,
                };
                // Record constant and convert to Value
                self.identified_constants.push(constant.clone());
                let value = crate::core_types::Value::from(constant);
                self.emit(Instruction::LDI(vr.0, value));
                Ok((vr, false)) // Return VR and its secrecy (false)
            }
            // --- Identifiers ---
            AstNode::Identifier(name, _location) => {
                // Semantic analysis already verified this identifier exists.
                // Look it up to get its register.
                if let Some(&vr_index) = self.symbol_table.get(name) {
                    let vr = VirtualRegister(vr_index);
                    let is_secret = *self
                        .vr_secrecy
                        .get(&vr)
                        .expect("Identifier VR missing from secrecy map");
                    Ok((vr, is_secret))
                } else {
                    // Builtin objects like ClientStore don't need registers - they're accessed via methods
                    // Just return a dummy register (this shouldn't be reached for properly transformed code)
                    Err(CompilerError::internal_error(format!(
                        "Codegen failed: Symbol '{}' passed semantic analysis but not found in codegen symbol table",
                        name
                    )))
                }
            }
            AstNode::VariableDeclaration {
                name,
                value,
                type_annotation,
                is_mutable: _,
                is_secret,
                location: _,
            } => {
                // Determine if the initial value needs a secret register
                // Secrecy comes from a `secret` type annotation.
                // Semantic analysis should have ensured consistency if both are present.
                let annotation_type = type_annotation.as_ref().map(|n| SymbolType::from_ast(n));
                let value_type_hint = value
                    .as_deref()
                    .and_then(|expr| self.type_hint_for_node(expr));
                let declared_type = annotation_type
                    .clone()
                    .or(value_type_hint.clone())
                    .unwrap_or(SymbolType::Unknown);
                let final_type = if declared_type.is_secret() || *is_secret {
                    declared_type.with_secret_modifier()
                } else {
                    declared_type
                };
                let explicit_secret = final_type.uses_secret_register();
                let value_share_type = value
                    .as_deref()
                    .and_then(|expr| self.share_type_for_node(expr));
                let value_share_list = value.as_deref().and_then(|expr| match expr {
                    AstNode::ListLiteral { elements, .. } => Some(
                        elements
                            .iter()
                            .map(|element| {
                                self.share_type_for_node(element)
                                    .unwrap_or_else(ShareType::default_secret_int)
                            })
                            .collect::<Vec<_>>(),
                    ),
                    AstNode::Identifier(identifier, _) => {
                        self.variable_share_lists.get(identifier).cloned()
                    }
                    _ => None,
                });

                let (value_vr, value_is_secret) = match value {
                    Some(val_expr) => {
                        let (vr, is_sec) = self.compile_node(val_expr)?; // Compile the expression first
                        let needs_secret = explicit_secret || is_sec;
                        let target_vr = self.allocate_virtual_register(needs_secret);
                        self.emit(Instruction::MOV(target_vr.0, vr.0));
                        (target_vr, needs_secret)
                    }
                    None => self.compile_default_value_for_type(&final_type, explicit_secret)?,
                };

                // Store the variable name and its register in the symbol table.
                self.symbol_table.insert(name.clone(), value_vr.0);
                self.symbol_types.insert(name.clone(), final_type);
                if let Some(share_types) = value_share_list {
                    self.variable_share_lists.insert(name.clone(), share_types);
                    self.variable_share_types.remove(name);
                } else if let Some(share_type) = value_share_type {
                    self.variable_share_types.insert(name.clone(), share_type);
                    self.variable_share_lists.remove(name);
                } else {
                    self.variable_share_types.remove(name);
                    self.variable_share_lists.remove(name);
                }
                if let Some(value) = value
                    .as_deref()
                    .and_then(|node| int_literal_u64(Some(node)))
                {
                    self.clear_int_constants.insert(name.clone(), value);
                } else {
                    self.clear_int_constants.remove(name);
                }
                // Update vr_secrecy map for this VR to ensure it has the correct flag
                self.vr_secrecy.insert(value_vr, value_is_secret);

                Ok((value_vr, value_is_secret)) // Return the VR holding the initial value and its secrecy
            }
            // --- Operations ---
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } => {
                let (operand_vr, operand_is_secret) = self.compile_node(operand)?;
                let result_is_secret = operand_is_secret; // Unary ops preserve secrecy
                let dest_vr = self.allocate_virtual_register(result_is_secret);

                match op.as_str() {
                    "-" => {
                        let zero_vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::I64(0));
                        self.emit(Instruction::LDI(
                            zero_vr.0,
                            crate::core_types::Value::from(Constant::I64(0)),
                        ));
                        self.emit(Instruction::SUB(dest_vr.0, zero_vr.0, operand_vr.0));
                    }
                    "not" => self.emit(Instruction::NOT(dest_vr.0, operand_vr.0)),
                    _ => {
                        return Err(CompilerError::semantic_error(
                            format!("Unsupported unary operator: {}", op),
                            location.clone(),
                        )
                        .with_hint("Supported unary operators are: - and not"));
                    }
                }

                Ok((dest_vr, result_is_secret))
            }
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } => {
                let (left_vr, left_is_secret) = self.compile_node(left)?;
                let (right_vr, right_is_secret) = self.compile_node(right)?;

                let mut result_is_secret = left_is_secret || right_is_secret;

                match op.as_str() {
                    "+" | "-" | "*" | "/" | "%" | // Arithmetic
                    "and" | "or" | "xor" | // Logical/Bitwise
                    "shl" | "shr" // Shifts
                    => {
                        let dest_vr = self.allocate_virtual_register(result_is_secret);
                        match op.as_str() {
                            "+" => self.emit(Instruction::ADD(dest_vr.0, left_vr.0, right_vr.0)),
                            "-" => self.emit(Instruction::SUB(dest_vr.0, left_vr.0, right_vr.0)),
                            "*" => self.emit(Instruction::MUL(dest_vr.0, left_vr.0, right_vr.0)),
                            "/" => self.emit(Instruction::DIV(dest_vr.0, left_vr.0, right_vr.0)),
                            "%" => self.emit(Instruction::MOD(dest_vr.0, left_vr.0, right_vr.0)),
                            "and" => self.emit(Instruction::AND(dest_vr.0, left_vr.0, right_vr.0)),
                            "or" => self.emit(Instruction::OR(dest_vr.0, left_vr.0, right_vr.0)),
                            "xor" => self.emit(Instruction::XOR(dest_vr.0, left_vr.0, right_vr.0)),
                            "shl" => self.emit(Instruction::SHL(dest_vr.0, left_vr.0, right_vr.0)),
                            "shr" => self.emit(Instruction::SHR(dest_vr.0, left_vr.0, right_vr.0)),
                            _ => unreachable!(),
                        }
                        Ok((dest_vr, result_is_secret))
                    }
                    "==" | "!=" | "<" | "<=" | ">" | ">=" => {
                        // Comparison operators produce a boolean result.
                        // Secrecy follows operands: secret if either side is secret.
                        result_is_secret = left_is_secret || right_is_secret;
                        let bool_dest_vr = self.allocate_virtual_register(result_is_secret);

                        // Emit CMP instruction
                        self.emit(Instruction::CMP(left_vr.0, right_vr.0));

                        // Emit the appropriate conditional jump
                        match op.as_str() {
                            "==" | "!=" | "<" | ">" => {
                                // Standard logic: Jump to true label if condition met
                                let true_label = format!("cmp_true_{}", self.current_instructions.len());
                                let end_label = format!("cmp_end_{}", self.current_instructions.len());

                                let jump_instruction = match op.as_str() {
                                    "==" => Instruction::JMPEQ(true_label.clone()),
                                    "!=" => Instruction::JMPNEQ(true_label.clone()),
                                    "<" => Instruction::JMPLT(true_label.clone()),
                                    ">" => Instruction::JMPGT(true_label.clone()),
                                    _ => unreachable!(),
                                };
                                self.emit(jump_instruction);

                                // If condition is false
                                // Load clear/secret false according to destination secrecy
                                self.identified_constants.push(Constant::Bool(false));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(false)));
                                self.emit(Instruction::JMP(end_label.clone()));

                                // Define the true label's position
                                self.add_label(true_label);
                                self.identified_constants.push(Constant::Bool(true));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(true)));

                                // Define the end label's position
                                self.add_label(end_label);
                            },
                            "<=" | ">=" => {
                                // Inverted logic: Jump to false label if opposite condition met
                                let false_label = format!("cmp_false_{}", self.current_instructions.len());
                                let end_label = format!("cmp_end_{}", self.current_instructions.len());

                                let jump_instruction = match op.as_str() {
                                    "<=" => Instruction::JMPGT(false_label.clone()), // Jump if >
                                    ">=" => Instruction::JMPLT(false_label.clone()), // Jump if <
                                    _ => unreachable!(),
                                };
                                self.emit(jump_instruction);

                                // If condition is true (jump not taken)
                                self.identified_constants.push(Constant::Bool(true));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(true)));
                                self.emit(Instruction::JMP(end_label.clone()));

                                // Define the false label's position
                                self.add_label(false_label);
                                self.identified_constants.push(Constant::Bool(false));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(false)));

                                // Define the end label's position
                                self.add_label(end_label);
                            },
                            _ => unreachable!(), // Should be covered by outer match
                        };

                        // left_vr and right_vr are used. bool_dest_vr is defined.
                        Ok((bool_dest_vr, result_is_secret))
                    },
                    _ => Err(CompilerError::semantic_error(format!("Unsupported binary operator: {}", op), location.clone())
                        .with_hint("Supported operators are: +, -, *, /, ==, !=, <, <=, >, >=".to_string())),
                }
            }
            // --- Assignment ---
            AstNode::Assignment {
                target,
                value,
                location,
            } => {
                match target.as_ref() {
                    AstNode::Identifier(name, _target_loc) => {
                        let (value_vr, _value_is_secret) = self.compile_node(value)?;
                        let dest_vr_index =
                            self.symbol_table.get(name).cloned().ok_or_else(|| {
                                CompilerError::internal_error(format!(
                                    "Assignment target '{}' not found in symbol table",
                                    name
                                ))
                            })?;
                        // The MOV instruction implicitly handles potential hide/reveal
                        // based on the source and destination register halves.
                        self.emit(Instruction::MOV(dest_vr_index, value_vr.0));

                        // Assignment itself doesn't produce a value/register to be used further.
                        if let Some(value) = int_literal_u64(Some(value.as_ref())) {
                            self.clear_int_constants.insert(name.clone(), value);
                        } else {
                            self.clear_int_constants.remove(name);
                        }
                        Ok(self.emit_unit_value())
                    }
                    AstNode::FieldAccess {
                        object,
                        field_name,
                        location: _,
                    } => {
                        // Compile object and value
                        let (obj_vr, _obj_is_secret) = self.compile_node(object)?;
                        let (val_vr, _val_is_secret) = self.compile_node(value)?;

                        // Load field name as string constant
                        let field_const = Constant::String(field_name.clone());
                        self.identified_constants.push(field_const.clone());
                        let field_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::LDI(
                            field_vr.0,
                            crate::core_types::Value::from(field_const),
                        ));

                        // Call set_field(object, field_name, value)
                        self.emit(Instruction::PUSHARG(obj_vr.0));
                        self.emit(Instruction::PUSHARG(field_vr.0));
                        self.emit(Instruction::PUSHARG(val_vr.0));
                        self.emit(Instruction::CALL("set_field".to_string()));

                        Ok(self.emit_unit_value())
                    }
                    AstNode::IndexAccess {
                        base,
                        index,
                        location: _,
                    } => {
                        // Compile base, index, and value
                        let (base_vr, _base_is_secret) = self.compile_node(base)?;
                        let (idx_vr, _idx_is_secret) = self.compile_node(index)?;
                        let (val_vr, _val_is_secret) = self.compile_node(value)?;

                        // Call set_field(base, index, value)
                        self.emit(Instruction::PUSHARG(base_vr.0));
                        self.emit(Instruction::PUSHARG(idx_vr.0));
                        self.emit(Instruction::PUSHARG(val_vr.0));
                        self.emit(Instruction::CALL("set_field".to_string()));

                        Ok(self.emit_unit_value())
                    }
                    _ => Err(CompilerError::semantic_error(
                        "Invalid assignment target",
                        location.clone(),
                    )),
                }
            }
            // --- Control Flow & Functions ---
            AstNode::FunctionCall {
                function,
                arguments,
                location: _,
                resolved_return_type,
            } => {
                if arguments.is_empty() && is_share_random_call(function) {
                    if let Some(return_type) = resolved_return_type.as_ref() {
                        if let Some(share_type) =
                            share_type_for_secret_scalar_symbol_type(return_type)
                        {
                            let bit_length = match share_type {
                                ShareType::SecretInt { bit_length } => bit_length,
                                ShareType::SecretFixedPoint { .. } => unreachable!(),
                            };
                            let bit_length_vr = self.allocate_virtual_register(false);
                            self.identified_constants
                                .push(Constant::I64(bit_length as i64));
                            self.emit(Instruction::LDI(
                                bit_length_vr.0,
                                crate::core_types::Value::from(Constant::I64(bit_length as i64)),
                            ));
                            self.emit(Instruction::PUSHARG(bit_length_vr.0));
                            self.emit(Instruction::CALL("Share.random_int".to_string()));

                            let result_vr = self.allocate_virtual_register(true);
                            self.emit(Instruction::MOV(result_vr.0, 0));
                            return Ok((result_vr, true));
                        }
                    }
                }

                if let (
                    AstNode::Identifier(function_name, _),
                    Some(SymbolType::Object(object_name)),
                ) = (function.as_ref(), resolved_return_type.as_ref())
                {
                    if function_name == object_name
                        && arguments
                            .iter()
                            .all(|arg| matches!(arg, AstNode::NamedArgument { .. }))
                    {
                        self.emit(Instruction::CALL("create_object".to_string()));

                        let obj_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(obj_vr.0, 0));

                        for arg in arguments {
                            let AstNode::NamedArgument {
                                name: field_name,
                                value,
                                ..
                            } = arg
                            else {
                                unreachable!("constructor arguments were checked above");
                            };

                            let (value_vr, _value_is_secret) = self.compile_node(value)?;

                            let field_const = Constant::String(field_name.clone());
                            self.identified_constants.push(field_const.clone());
                            let field_vr = self.allocate_virtual_register(false);
                            self.emit(Instruction::LDI(
                                field_vr.0,
                                crate::core_types::Value::from(field_const),
                            ));

                            self.emit(Instruction::PUSHARG(obj_vr.0));
                            self.emit(Instruction::PUSHARG(field_vr.0));
                            self.emit(Instruction::PUSHARG(value_vr.0));
                            self.emit(Instruction::CALL("set_field".to_string()));
                        }

                        return Ok((obj_vr, false));
                    }
                }

                // 1. Identify the function name
                // Semantic analysis already verified the function exists and is callable.
                let raw_function_name =
                    match function.as_ref() {
                        AstNode::Identifier(name, _) => name.clone(),
                        // Semantic analysis should have caught non-identifier calls if unsupported
                        _ => return Err(CompilerError::internal_error(
                            "Codegen expected identifier for function call after semantic analysis"
                                .to_string(),
                        )),
                    };

                // 2. Map source-level builtin aliases to actual VM function names.
                let function_name = crate::builtin_registry::builtin_registry()
                    .vm_symbol_for_call(&raw_function_name)
                    .map(str::to_string)
                    .unwrap_or(raw_function_name);

                self.record_client_io_call(&function_name, arguments);
                self.record_share_list_append_call(&function_name, arguments);

                // 3. Compile arguments first (do NOT emit PUSHARG yet) to keep PUSHARGs contiguous before CALL
                let mut arg_vrs = Vec::with_capacity(arguments.len());
                for arg in arguments {
                    let (arg_vr, _arg_is_secret) = self.compile_node(arg)?;
                    arg_vrs.push(arg_vr);
                }
                // After all arguments are compiled, emit contiguous PUSHARGs in order
                for vr in &arg_vrs {
                    self.emit(Instruction::PUSHARG(vr.0));
                }

                // 4. Determine result type and secrecy from resolved type (added by semantic analysis)
                let return_type = resolved_return_type
                    .as_ref()
                    .cloned()
                    .unwrap_or(SymbolType::Unknown);

                let result_is_secret = return_type.uses_secret_register();
                let result_vr = self.allocate_virtual_register(result_is_secret);

                self.emit(Instruction::CALL(function_name.clone()));
                // Only move the result if the function actually returns something
                if return_type != SymbolType::Void {
                    self.emit(Instruction::MOV(result_vr.0, 0)); // Assume result is in r0 (physical) after call
                }

                Ok((result_vr, result_is_secret)) // Return the VR holding the result
            }
            AstNode::NamedArgument { location, .. } => Err(CompilerError::internal_error(format!(
                "Codegen received named argument outside object constructor at {}:{}",
                location.line, location.column
            ))),
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                let (condition_vr, condition_is_secret) = self.compile_node(condition)?;
                if condition_is_secret {
                    return Err(CompilerError::semantic_error(
                        "Cannot use secret value as condition in 'if'",
                        condition.location(),
                    ));
                }

                // Compare the boolean condition VR against Bool(false)
                // Note: Condition itself is already boolean, but CMP sets flags for jumps.
                let false_vr = self.allocate_virtual_register(false); // false is clear
                self.identified_constants.push(Constant::Bool(false));
                self.emit(Instruction::LDI(
                    false_vr.0,
                    crate::core_types::Value::Bool(false),
                ));
                self.emit(Instruction::CMP(condition_vr.0, false_vr.0)); // Compare condition == false

                let else_label = format!("else_{}", self.current_instructions.len());
                let end_label = format!("end_if_{}", self.current_instructions.len());

                // Jump to else when condition == false
                self.emit(Instruction::JMPEQ(else_label.clone()));

                // --- Then Branch ---
                let (then_vr, then_is_secret) = self.compile_node(then_branch)?;
                // Provisional result register uses then-branch secrecy; may be updated after else
                let result_is_secret = then_is_secret;
                let result_vr = self.allocate_virtual_register(result_is_secret);
                self.emit(Instruction::MOV(result_vr.0, then_vr.0));
                // Skip else branch after executing then branch
                self.emit(Instruction::JMP(end_label.clone()));

                // --- Else Branch ---
                self.add_label(else_label);
                let (else_vr, else_is_secret) = match else_branch.as_deref() {
                    Some(branch) => self.compile_node(branch)?,
                    None => {
                        // If no else, evaluate to Unit (clear)
                        let vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::Unit);
                        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
                        (vr, false)
                    }
                };
                // Update secrecy if needed (result is secret if either branch is secret)
                let final_result_is_secret = result_is_secret || else_is_secret;
                if final_result_is_secret != result_is_secret {
                    // Update secrecy map so allocator places this VR into correct bank
                    self.vr_secrecy.insert(result_vr, final_result_is_secret);
                }
                self.emit(Instruction::MOV(result_vr.0, else_vr.0));

                // --- End Label ---
                self.add_label(end_label);
                Ok((result_vr, final_result_is_secret))
            }
            AstNode::Block(nodes) => {
                let mut last_vr = self.allocate_virtual_register(false); // Default VR for empty block (clear)
                let mut last_vr_is_secret = false;
                for node in nodes {
                    (last_vr, last_vr_is_secret) = self.compile_node(node)?;
                }
                Ok((last_vr, last_vr_is_secret))
            }
            AstNode::Return { value, location: _ } => {
                // Determine secrecy based on function signature's return type (TODO)
                let (value_vr, value_is_secret) = match value {
                    Some(v) => self.compile_node(v)?,
                    None => {
                        // Return Unit (assume clear default)
                        let vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::Unit);
                        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
                        (vr, false)
                    }
                };
                // Return the value directly from its virtual register; the VM will place it in caller's R0.
                self.emit(Instruction::RET(value_vr.0));
                Ok((value_vr, value_is_secret)) // Return VR, though RET is terminal
            }
            AstNode::DiscardStatement {
                expression,
                location: _,
            } => {
                let (vr, is_secret) = self.compile_node(expression)?;
                // The VR's live range ends here. Allocator handles it.
                Ok((vr, is_secret)) // Return the VR, but its value isn't used further
            }
            AstNode::FieldAccess {
                object,
                field_name,
                location: _,
            } => {
                let (object_vr, _object_is_secret) = self.compile_node(object)?;

                // Load field name as string constant
                let field_const = Constant::String(field_name.clone());
                self.identified_constants.push(field_const.clone());
                let field_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::LDI(
                    field_vr.0,
                    crate::core_types::Value::from(field_const),
                ));

                // Call get_field(object, field_name)
                self.emit(Instruction::PUSHARG(object_vr.0));
                self.emit(Instruction::PUSHARG(field_vr.0));
                self.emit(Instruction::CALL("get_field".to_string()));

                let result_is_secret = self
                    .type_hint_for_node(node)
                    .is_some_and(|ty| ty.uses_secret_register());
                let result_vr = self.allocate_virtual_register(result_is_secret);
                self.emit(Instruction::MOV(result_vr.0, 0)); // Result is in r0

                Ok((result_vr, result_is_secret))
            }
            AstNode::WhileLoop {
                condition,
                body,
                location: _,
            } => {
                let loop_start_label = format!("loop_start_{}", self.current_instructions.len());
                let end_loop_label = format!("loop_end_{}", self.current_instructions.len());
                let loop_bound = self.loop_bound_for_condition(condition);

                // Define the label for the start of the loop (condition check)
                self.add_label(loop_start_label.clone());

                // Compile condition (assume clear for CMP/JMP)
                let (condition_vr, condition_is_secret) = self.compile_node(condition)?;
                if condition_is_secret {
                    return Err(CompilerError::semantic_error(
                        "Cannot use secret value as condition in 'while'",
                        condition.location(),
                    ));
                }

                // Compare the boolean condition VR against Bool(false)
                let false_vr = self.allocate_virtual_register(false); // false is clear
                self.identified_constants.push(Constant::Bool(false));
                self.emit(Instruction::LDI(
                    false_vr.0,
                    crate::core_types::Value::Bool(false),
                ));
                self.emit(Instruction::CMP(condition_vr.0, false_vr.0)); // Compare condition == false

                self.emit(Instruction::JMPEQ(end_loop_label.clone()));
                // condition_vr, false_vr used up to here.

                if let Some((loop_var, bound)) = loop_bound {
                    self.active_loop_bounds.push((loop_var, bound));
                    let body_result = self.compile_node(body);
                    self.active_loop_bounds.pop();
                    let (_body_vr, _body_is_secret) = body_result?;
                } else {
                    let (_body_vr, _body_is_secret) = self.compile_node(body)?;
                }
                // Result of body is discarded. Its live range ends.

                // Jump back to condition check
                self.emit(Instruction::JMP(loop_start_label));

                // Define the end label's position
                self.add_label(end_loop_label);

                // While loops evaluate to Unit
                let nil_vr = self.allocate_virtual_register(false); // Unit is clear
                self.identified_constants.push(Constant::Unit);
                self.emit(Instruction::LDI(nil_vr.0, crate::core_types::Value::Unit));
                Ok((nil_vr, false))
            }
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                location,
            } => {
                // Support: single var over range a .. b (exclusive) or over a list/array
                if variables.len() != 1 {
                    return Err(CompilerError::semantic_error(
                        "For-loop with multiple variables not supported yet",
                        location.clone(),
                    ));
                }

                let var_name = variables[0].clone();

                // Check if iterable is a range or a collection
                match iterable.as_ref() {
                    AstNode::BinaryOperation {
                        op,
                        left,
                        right,
                        location: _,
                    } if op == ".." => {
                        // Range iteration: for i in start..end, excluding end
                        let (start_vr, start_is_secret) = self.compile_node(left)?;
                        let (end_vr, end_is_secret) = self.compile_node(right)?;
                        if start_is_secret || end_is_secret {
                            return Err(CompilerError::semantic_error(
                                "Secret values are not supported in for-loop range bounds",
                                iterable.location(),
                            ));
                        }

                        // Allocate loop variable (clear) and initialize with start
                        let loop_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(loop_vr.0, start_vr.0));

                        // Insert loop variable into symbol table, saving any previous binding
                        let prev_binding = self.symbol_table.insert(var_name.clone(), loop_vr.0);

                        // Labels
                        let loop_start_label =
                            format!("for_start_{}", self.current_instructions.len());
                        let loop_end_label = format!("for_end_{}", self.current_instructions.len());

                        // Start label
                        self.add_label(loop_start_label.clone());

                        // If i >= end: exit
                        self.emit(Instruction::CMP(loop_vr.0, end_vr.0));
                        self.emit(Instruction::JMPGT(loop_end_label.clone()));
                        self.emit(Instruction::JMPEQ(loop_end_label.clone()));

                        // Body
                        let (_body_vr, _body_is_secret) = self.compile_node(body)?;

                        // i = i + 1
                        let one_vr = self.allocate_virtual_register(false);
                        let one_val = crate::core_types::Value::from(Constant::I64(1));
                        self.identified_constants.push(Constant::I64(1));
                        self.emit(Instruction::LDI(one_vr.0, one_val));
                        self.emit(Instruction::ADD(loop_vr.0, loop_vr.0, one_vr.0));

                        // Keep the upper bound (end_vr) live across the body to avoid clobbering by temps
                        let end_keepalive = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(end_keepalive.0, end_vr.0));

                        // Jump back
                        self.emit(Instruction::JMP(loop_start_label));

                        // End label
                        self.add_label(loop_end_label);

                        // Restore/cleanup symbol table mapping
                        match prev_binding {
                            Some(old_idx) => {
                                self.symbol_table.insert(var_name, old_idx);
                            }
                            None => {
                                self.symbol_table.remove(&variables[0]);
                            }
                        }
                    }
                    _ => {
                        // Collection iteration: for item in list
                        // Compile the collection expression
                        let (collection_vr, collection_is_secret) = self.compile_node(iterable)?;

                        // Get the length of the collection: array_length(collection)
                        self.emit(Instruction::PUSHARG(collection_vr.0));
                        self.emit(Instruction::CALL("array_length".to_string()));
                        let len_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(len_vr.0, 0)); // Result is in r0

                        // Allocate index variable (internal, starts at 0)
                        let index_vr = self.allocate_virtual_register(false);
                        let zero_vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::I64(0));
                        self.emit(Instruction::LDI(
                            zero_vr.0,
                            crate::core_types::Value::from(Constant::I64(0)),
                        ));
                        self.emit(Instruction::MOV(index_vr.0, zero_vr.0));

                        // Allocate the loop element variable in the same bank as the iterable.
                        // The current bytecode does not carry element-level secrecy metadata, so
                        // clear collections must stay in clear registers to avoid accidental MPC
                        // execution during ordinary local loops.
                        let elem_vr = self.allocate_virtual_register(collection_is_secret);

                        // Insert loop variable (element) into symbol table
                        let prev_binding = self.symbol_table.insert(var_name.clone(), elem_vr.0);

                        // Labels
                        let loop_start_label =
                            format!("for_start_{}", self.current_instructions.len());
                        let loop_end_label = format!("for_end_{}", self.current_instructions.len());

                        // Start label
                        self.add_label(loop_start_label.clone());

                        // If index >= len: exit
                        self.emit(Instruction::CMP(index_vr.0, len_vr.0));
                        self.emit(Instruction::JMPGT(loop_end_label.clone()));
                        self.emit(Instruction::JMPEQ(loop_end_label.clone()));

                        // Get element: elem = get_field(collection, index)
                        self.emit(Instruction::PUSHARG(collection_vr.0));
                        self.emit(Instruction::PUSHARG(index_vr.0));
                        self.emit(Instruction::CALL("get_field".to_string()));
                        self.emit(Instruction::MOV(elem_vr.0, 0)); // Result is in r0

                        // Body
                        let (_body_vr, _body_is_secret) = self.compile_node(body)?;

                        // index = index + 1
                        let one_vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::I64(1));
                        self.emit(Instruction::LDI(
                            one_vr.0,
                            crate::core_types::Value::from(Constant::I64(1)),
                        ));
                        self.emit(Instruction::ADD(index_vr.0, index_vr.0, one_vr.0));

                        // Keep collection and length alive across the body
                        let collection_keepalive =
                            self.allocate_virtual_register(collection_is_secret);
                        self.emit(Instruction::MOV(collection_keepalive.0, collection_vr.0));
                        let len_keepalive = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(len_keepalive.0, len_vr.0));

                        // Jump back
                        self.emit(Instruction::JMP(loop_start_label));

                        // End label
                        self.add_label(loop_end_label);

                        // Restore/cleanup symbol table mapping
                        match prev_binding {
                            Some(old_idx) => {
                                self.symbol_table.insert(var_name, old_idx);
                            }
                            None => {
                                self.symbol_table.remove(&variables[0]);
                            }
                        }
                    }
                }

                // For-loops evaluate to Unit
                let nil_vr = self.allocate_virtual_register(false);
                self.identified_constants.push(Constant::Unit);
                self.emit(Instruction::LDI(nil_vr.0, crate::core_types::Value::Unit));
                Ok((nil_vr, false))
            }
            AstNode::FunctionDefinition {
                name,
                type_params,
                parameters,
                return_type: _,
                body,
                is_secret: _,
                pragmas,
                location,
                node_id: _,
            } => {
                // --- Check for Pragmas ---
                let mut skip_compilation = false;
                for pragma in pragmas {
                    let pragma_name = match pragma {
                        Pragma::Simple(name, _) => name,
                        Pragma::KeyValue(name, _, _) => name,
                    };

                    if let Some(handler) = self.pragma_handlers.get(pragma_name) {
                        handler(self, node, pragma)?;
                        // Check if the handler indicates compilation should be skipped
                        if pragma_name == "builtin" {
                            // Register the function name as a known built-in.
                            if let Some(name) = name {
                                self.known_builtins.insert(name.clone());
                            }
                            skip_compilation = true;
                        }
                    }
                }
                if skip_compilation {
                    return Ok((VirtualRegister(usize::MAX), false)); // Indicate success, no VR
                }
                // --- Compile the function body ---
                let mut function_generator = CodeGenerator::new();
                function_generator.object_field_types = self.object_field_types.clone();

                // --- Add parameters to the function_generator's symbol table ---
                let mut param_vrs: Vec<VirtualRegister> = Vec::new();
                for param in parameters.iter() {
                    // Determine parameter secrecy from its type annotation
                    let param_type = param
                        .type_annotation
                        .as_ref()
                        .map(|n| SymbolType::from_ast_with_type_params(n, type_params))
                        .unwrap_or(SymbolType::Unknown);
                    let param_is_secret = param_type.uses_secret_register();
                    // Allocate a virtual register for the parameter. These will typically
                    let param_vr = function_generator.allocate_virtual_register(param_is_secret);
                    let local_vr = function_generator.allocate_virtual_register(param_is_secret);
                    function_generator.emit(Instruction::MOV(local_vr.0, param_vr.0));
                    function_generator
                        .symbol_table
                        .insert(param.name.clone(), local_vr.0); // Store copied local VR index
                    function_generator
                        .symbol_types
                        .insert(param.name.clone(), param_type);
                    param_vrs.push(param_vr);
                }

                // Compile the function body using the new generator.
                let (_body_result_reg, _body_is_secret) = function_generator.compile_node(body)?;
                self.merge_client_io_from(&function_generator);

                // --- Perform Register Allocation ---
                let virtual_instructions = function_generator.current_instructions;
                let intervals = register_allocator::analyze_liveness_cfg_with_liveins(
                    &virtual_instructions,
                    &function_generator.current_labels,
                    &param_vrs,
                );
                let graph = register_allocator::build_interference_graph(&intervals);

                let k_clear = SECRET_REGISTER_START;
                let k_secret = MAX_REGISTERS - k_clear;
                let secrecy_map = function_generator.vr_secrecy;

                // Precolor parameter VRs to ABI registers R0..Rn-1
                let mut precolored: HashMap<VirtualRegister, PhysicalRegister> = HashMap::new();
                for (i, vr) in param_vrs.iter().enumerate() {
                    precolored.insert(*vr, PhysicalRegister(i));
                }

                let allocation_result = register_allocator::color_graph(
                    &graph,
                    k_clear,
                    k_secret,
                    &secrecy_map,
                    &precolored,
                );
                let allocation = match allocation_result {
                    Ok(alloc) => alloc,
                    Err(AllocationError::NeedsSpilling(spilled_vrs)) => {
                        // Basic error handling for now. Real implementation needs spilling logic.
                        return Err(CompilerError::internal_error(format!(
                            "Register allocation failed for function '{}': Need to spill registers {:?}",
                            name.as_deref().unwrap_or("<anon>"), spilled_vrs
                        )).with_hint("Spilling not yet implemented. Try simplifying the function."));
                    }
                    Err(AllocationError::PoolExhausted(_, _)) => {
                        return Err(CompilerError::internal_error(
                            "Register allocation failed: Pool exhausted".to_string(),
                        ));
                    }
                };

                // Rewrite instructions with physical registers
                let final_instructions =
                    register_allocator::rewrite_instructions(&virtual_instructions, &allocation);

                // Finalize the function's bytecode chunk.
                let mut function_chunk = BytecodeChunk::new();
                function_chunk.instructions = final_instructions;
                function_chunk.labels = function_generator.current_labels; // TODO: Adjust label indices after rewrite/spilling?
                function_chunk.constants =
                    dedupe_constants(function_generator.identified_constants);
                function_chunk.parameters =
                    parameters.iter().map(|param| param.name.clone()).collect();
                function_chunk.upvalues = collect_upvalue_names(body);

                // Store the compiled chunk appropriately.
                if let Some(func_name) = name {
                    if func_name == "main" {
                        // `def main(...)` is the program entry.
                        if self.main_proc_chunk.is_some() {
                            return Err(CompilerError::semantic_error(
                                "Multiple 'main' procedures defined".to_string(),
                                location.clone(),
                            ));
                        }
                        self.main_proc_chunk = Some(function_chunk);
                    } else {
                        // Detect explicit entry: allow pragma "entry" for now; otherwise store as normal function.
                        if self.compiled_functions.contains_key(func_name) {
                            // TODO: Allow overloading later?
                            return Err(CompilerError::semantic_error(
                                format!("Function '{}' already defined", func_name),
                                location.clone(),
                            ));
                        }
                        let is_entry = pragmas
                            .iter()
                            .any(|p| matches!(p, Pragma::Simple(n, _) if n == "entry"));
                        if is_entry {
                            if self.entry_main_chunk.is_some() {
                                return Err(CompilerError::semantic_error(
                                    "Multiple explicit 'main' entries defined".to_string(),
                                    location.clone(),
                                )
                                .with_hint("Only one entry function is allowed"));
                            }
                            self.entry_main_chunk = Some(function_chunk.clone());
                        }
                        self.compiled_functions
                            .insert(func_name.clone(), function_chunk);
                    }
                } else {
                    // TODO: Handle anonymous functions (lambdas)
                    return Err(CompilerError::internal_error(
                        "Anonymous function definition not yet supported".to_string(),
                    ));
                }

                // Function definition itself doesn't produce a value in the outer scope.
                Ok((VirtualRegister(usize::MAX), false)) // Return dummy VR
            }
            AstNode::ObjectDefinition {
                name,
                base_type: _,
                fields,
                is_secret: _,
                location: _,
            } => {
                // Object definitions are type declarations - no bytecode is generated.
                // The type information is registered in semantic analysis.
                // At runtime, objects are created via constructor calls (to be implemented).
                //
                // For now, we just register the object type's field information for later use
                // when compiling object instantiation and field access.
                //
                let field_types = fields
                    .iter()
                    .map(|field| {
                        let mut field_type = SymbolType::from_ast(&field.type_annotation);
                        if field.is_secret && !field_type.is_secret() {
                            field_type = field_type.with_secret_modifier();
                        }
                        (field.name.clone(), field_type)
                    })
                    .collect::<Vec<_>>();
                self.object_field_types.insert(name.clone(), field_types);

                // Object definition doesn't produce a runtime value
                Ok((VirtualRegister(usize::MAX), false))
            }
            AstNode::TypeAlias { .. }
            | AstNode::BuiltinTypeDefinition { .. }
            | AstNode::BuiltinObjectDefinition { .. } => {
                // These declarations are compile-time metadata only.
                Ok((VirtualRegister(usize::MAX), false))
            }
            AstNode::ListLiteral { elements, .. } => {
                // Create array with capacity
                let capacity_const = Constant::I64(elements.len() as i64);
                self.identified_constants.push(capacity_const.clone());
                let cap_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::LDI(
                    cap_vr.0,
                    crate::core_types::Value::from(capacity_const),
                ));
                self.emit(Instruction::PUSHARG(cap_vr.0));
                self.emit(Instruction::CALL("create_array".to_string()));

                let array_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::MOV(array_vr.0, 0)); // Result is in r0

                // Push each element using array_push
                for elem in elements {
                    let (elem_vr, _elem_is_secret) = self.compile_node(elem)?;
                    self.emit(Instruction::PUSHARG(array_vr.0));
                    self.emit(Instruction::PUSHARG(elem_vr.0));
                    self.emit(Instruction::CALL("array_push".to_string()));
                }

                Ok((array_vr, false))
            }
            AstNode::DictLiteral { pairs, .. } => {
                // Create object
                self.emit(Instruction::CALL("create_object".to_string()));

                let obj_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::MOV(obj_vr.0, 0)); // Result is in r0

                // Set each key-value pair using set_field
                for (key, value) in pairs {
                    let (key_vr, _key_is_secret) = self.compile_node(key)?;
                    let (val_vr, _val_is_secret) = self.compile_node(value)?;

                    self.emit(Instruction::PUSHARG(obj_vr.0));
                    self.emit(Instruction::PUSHARG(key_vr.0));
                    self.emit(Instruction::PUSHARG(val_vr.0));
                    self.emit(Instruction::CALL("set_field".to_string()));
                }

                Ok((obj_vr, false))
            }
            AstNode::IndexAccess {
                base,
                index,
                location: _,
            } => {
                let (base_vr, base_is_secret) = self.compile_node(base)?;
                let (index_vr, index_is_secret) = self.compile_node(index)?;

                // Call get_field(base, index)
                self.emit(Instruction::PUSHARG(base_vr.0));
                self.emit(Instruction::PUSHARG(index_vr.0));
                self.emit(Instruction::CALL("get_field".to_string()));

                let result_is_secret = base_is_secret
                    || index_is_secret
                    || self
                        .type_hint_for_node(node)
                        .is_some_and(|ty| ty.uses_secret_register());
                let result_vr = self.allocate_virtual_register(result_is_secret);
                self.emit(Instruction::MOV(result_vr.0, 0)); // Result is in r0

                Ok((result_vr, result_is_secret))
            }
            // Import statements are processed at the multi-file compilation level
            // and don't generate any bytecode themselves
            AstNode::Import { .. } => {
                // Imports are a no-op in codegen - they're handled during semantic analysis
                Ok((VirtualRegister(0), false))
            }
            _ => Err(CompilerError::internal_error(format!(
                "Codegen not implemented for AST node: {:?}",
                node
            ))),
        }
    }

    /// Finalizes the entire compiled program, including the main chunk and all function chunks.
    fn finalize_program(mut self) -> CompilerResult<CompiledProgram> {
        let client_io_manifest = self.client_io_manifest();

        // If both an explicit entry and `def main` exist, error clearly.
        if self.entry_main_chunk.is_some() && self.main_proc_chunk.is_some() {
            return Err(CompilerError::semantic_error(
                "Both explicit 'main' and 'def main' entries are defined".to_string(),
                crate::errors::SourceLocation::default(),
            )
            .with_hint("Use only one entry point; prefer 'def main(...)'"));
        }

        // If explicit entry is set, ensure no top-level code and use it as entry chunk.
        if let Some(entry_chunk) = self.entry_main_chunk.take() {
            if !self.current_instructions.is_empty() {
                return Err(CompilerError::semantic_error(
                    "Cannot mix top-level code with explicit 'main' entry".to_string(),
                    crate::errors::SourceLocation::default(),
                )
                .with_hint("Move top-level code into the entry function declared with 'main'"));
            }
            return Ok(CompiledProgram {
                main_chunk: entry_chunk,
                function_chunks: self.compiled_functions,
                client_io_manifest,
            });
        }
        // `def main(...)` is an entry chunk and cannot be mixed with top-level code.
        if let Some(main_proc) = self.main_proc_chunk.take() {
            if self.current_instructions.is_empty() {
                return Ok(CompiledProgram {
                    main_chunk: main_proc,
                    function_chunks: self.compiled_functions,
                    client_io_manifest,
                });
            } else {
                return Err(CompilerError::semantic_error(
                    "Cannot mix top-level code with 'def main' entry".to_string(),
                    crate::errors::SourceLocation::default(),
                )
                .with_hint("Move top-level code into 'def main(...)'"));
            }
        }

        // If there are no top-level instructions but a 'main' function exists,
        // insert a call to 'main' so the program entry has executable bytecode.
        if self.current_instructions.is_empty() && self.compiled_functions.contains_key("main") {
            self.current_instructions
                .push(Instruction::CALL("main".to_string()));
        }
        // Perform register allocation for the main chunk's instructions
        let main_instructions = self.current_instructions; // Instructions generated for the main body
        let intervals = register_allocator::analyze_liveness_cfg_with_liveins(
            &main_instructions,
            &self.current_labels,
            &[],
        );
        let graph = register_allocator::build_interference_graph(&intervals);

        let k_clear = SECRET_REGISTER_START;
        let k_secret = MAX_REGISTERS - k_clear;
        let secrecy_map = self.vr_secrecy;
        // No precolored mapping for top-level/main chunk
        let empty_pre: HashMap<VirtualRegister, PhysicalRegister> = HashMap::new();
        let allocation_result =
            register_allocator::color_graph(&graph, k_clear, k_secret, &secrecy_map, &empty_pre);
        let allocation = match allocation_result {
            Ok(alloc) => alloc,
            Err(AllocationError::NeedsSpilling(spilled_vrs)) => {
                // Basic error handling for now. Real implementation needs spilling logic.
                return Err(CompilerError::internal_error(format!(
                    "Register allocation failed for main program body: Need to spill registers {:?}",
                    spilled_vrs
                )).with_hint("Spilling not yet implemented."));
            }
            Err(AllocationError::PoolExhausted(_, _)) => {
                return Err(CompilerError::internal_error(
                    "Register allocation failed: Pool exhausted".to_string(),
                ));
            }
        };

        let final_main_instructions =
            register_allocator::rewrite_instructions(&main_instructions, &allocation);
        let mut main_chunk = BytecodeChunk::new();
        main_chunk.instructions = final_main_instructions;
        main_chunk.labels = self.current_labels; // TODO: Adjust label indices?
        main_chunk.constants = dedupe_constants(self.identified_constants);

        Ok(CompiledProgram {
            main_chunk,
            function_chunks: self.compiled_functions,
            client_io_manifest,
        })
    }
}

// --- Pragma Handler Implementations ---

/// Handles the `{.builtin.}` pragma.
/// This function is called when the "builtin" pragma is encountered during code generation.
fn handle_builtin_pragma(
    _generator: &mut CodeGenerator, // We need this to register the name
    _func_def_node: &AstNode,       // The FunctionDefinition node
    _pragma: &Pragma,               // The specific pragma node
) -> CompilerResult<()> {
    // The core logic for 'builtin' is simply *not* compiling the body.
    Ok(())
}

fn dedupe_constants(constants: Vec<Constant>) -> Vec<Constant> {
    use std::collections::HashSet;
    let mut seen: HashSet<crate::core_types::Value> = HashSet::new();
    let mut out = Vec::with_capacity(constants.len());
    for c in constants.into_iter() {
        let v = crate::core_types::Value::from(c.clone());
        if seen.insert(v) {
            out.push(c);
        }
    }
    out
}

fn collect_upvalue_names(node: &AstNode) -> Vec<String> {
    fn visit(node: &AstNode, out: &mut Vec<String>) {
        match node {
            AstNode::FunctionCall {
                function,
                arguments,
                ..
            } => {
                if let AstNode::Identifier(name, _) = function.as_ref() {
                    if matches!(name.as_str(), "get_upvalue" | "set_upvalue") {
                        if let Some(AstNode::Literal {
                            value: crate::ast::Value::String(upvalue),
                            ..
                        }) = arguments.first()
                        {
                            if !out.contains(upvalue) {
                                out.push(upvalue.clone());
                            }
                        }
                    }
                }

                visit(function, out);
                for argument in arguments {
                    visit(argument, out);
                }
            }
            AstNode::Block(statements) => {
                for statement in statements {
                    visit(statement, out);
                }
            }
            AstNode::VariableDeclaration {
                value: Some(value), ..
            } => visit(value, out),
            AstNode::VariableDeclaration { value: None, .. } => {}
            AstNode::Assignment { target, value, .. } => {
                visit(target, out);
                visit(value, out);
            }
            AstNode::Return {
                value: Some(value), ..
            } => visit(value, out),
            AstNode::Return { value: None, .. } => {}
            AstNode::DiscardStatement { expression, .. } => visit(expression, out),
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                visit(condition, out);
                visit(then_branch, out);
                if let Some(else_branch) = else_branch {
                    visit(else_branch, out);
                }
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                visit(condition, out);
                visit(body, out);
            }
            AstNode::ForLoop { iterable, body, .. } => {
                visit(iterable, out);
                visit(body, out);
            }
            AstNode::BinaryOperation { left, right, .. } => {
                visit(left, out);
                visit(right, out);
            }
            AstNode::UnaryOperation { operand, .. } => visit(operand, out),
            AstNode::NamedArgument { value, .. } => visit(value, out),
            AstNode::FieldAccess { object, .. } => visit(object, out),
            AstNode::IndexAccess { base, index, .. } => {
                visit(base, out);
                visit(index, out);
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => {
                for element in elements {
                    visit(element, out);
                }
            }
            AstNode::DictLiteral { pairs, .. } => {
                for (key, value) in pairs {
                    visit(key, out);
                    visit(value, out);
                }
            }
            AstNode::CommandCall {
                command, arguments, ..
            } => {
                visit(command, out);
                for argument in arguments {
                    visit(argument, out);
                }
            }
            AstNode::FunctionDefinition { .. } => {}
            _ => {}
        }
    }

    let mut upvalues = Vec::new();
    visit(node, &mut upvalues);
    upvalues
}

pub fn generate_bytecode(node: &AstNode) -> CompilerResult<CompiledProgram> {
    let mut generator = CodeGenerator::new();
    let (_result_vr, _result_is_secret) = generator.compile_node(node)?;
    generator.finalize_program()
}

#[cfg(test)]
mod tests {
    use super::{dedupe_constants, Constant};

    #[test]
    fn dedupe_removes_duplicates_and_preserves_order() {
        let input = vec![
            Constant::I64(1),
            Constant::Bool(true),
            Constant::I64(1), // dup
            Constant::String("a".into()),
            Constant::String("a".into()), // dup
            Constant::Unit,
            Constant::Unit,       // dup
            Constant::Bool(true), // dup
            Constant::I64(2),
        ];

        let out = dedupe_constants(input);

        assert_eq!(out.len(), 5, "Expected 5 unique constants");
        assert!(matches!(out[0], Constant::I64(1)));
        assert!(matches!(out[1], Constant::Bool(true)));
        assert!(matches!(out[2], Constant::String(ref s) if s == "a"));
        assert!(matches!(out[3], Constant::Unit));
        assert!(matches!(out[4], Constant::I64(2)));
    }
}
