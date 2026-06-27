//! # Function System for StoffelVM
//!
//! This module defines the function types and related functionality for the StoffelVM.
//! The VM supports two primary function types:
//!
//! 1. `VMFunction` - Functions defined in the VM's instruction set
//! 2. `ForeignFunction` - Functions implemented in Rust and exposed to the VM
//!
//! The module also provides the infrastructure for function resolution, closure creation,
//! and the Foreign Function Interface (FFI) system that bridges Rust and the VM.
//!
//! Functions in StoffelVM support:
//! - Parameter passing
//! - Return values
//! - Lexical scoping with upvalues
//! - Nested function definitions
//! - First-class functions and closures

use crate::core_types::Value;
use crate::instructions::Instruction;
use crate::registers::MIN_FRAME_REGISTER_COUNT;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::instructions::ResolvedInstruction;
use smallvec::SmallVec;

pub type FunctionResult<T> = Result<T, FunctionError>;
type ResolvedFunctionParts = (
    SmallVec<[ResolvedInstruction; 32]>,
    SmallVec<[Value; 16]>,
    SmallVec<[String; 16]>,
);

#[derive(Debug, Clone)]
pub struct ResolvedFunctionHeader {
    pub name: String,
    pub parameters: Vec<String>,
    pub upvalues: Vec<String>,
    pub parent: Option<String>,
    pub register_count: usize,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionError {
    ParametersExceedRegisters {
        function: String,
        parameters: usize,
        registers: usize,
    },
    LabelOutOfBounds {
        function: String,
        label: String,
        target: usize,
        instruction_count: usize,
    },
    UnknownLabel {
        function: String,
        label: String,
    },
    RegisterOutOfBounds {
        function: String,
        instruction_index: usize,
        register: usize,
        register_count: usize,
    },
    RegisterIndexOverflow {
        function: String,
        register: usize,
    },
    ResolvedOperandOverflow {
        function: String,
        operand: &'static str,
        value: usize,
    },
}

impl fmt::Display for FunctionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionError::ParametersExceedRegisters {
                function,
                parameters,
                registers,
            } => write!(
                f,
                "Function {function} declares {parameters} parameters but only {registers} registers"
            ),
            FunctionError::LabelOutOfBounds {
                function,
                label,
                target,
                instruction_count,
            } => write!(
                f,
                "Function {function} label '{label}' points past the instruction stream: {target} > {instruction_count}"
            ),
            FunctionError::UnknownLabel { function, label } => {
                write!(f, "Function {function} references unknown label '{label}'")
            }
            FunctionError::RegisterOutOfBounds {
                function,
                instruction_index,
                register,
                register_count,
            } => write!(
                f,
                "Function {function} instruction {instruction_index} references register r{register} but only {register_count} registers are declared"
            ),
            FunctionError::RegisterIndexOverflow { function, register } => write!(
                f,
                "Function {function} references register r{register}, which cannot fit in a frame register count"
            ),
            FunctionError::ResolvedOperandOverflow {
                function,
                operand,
                value,
            } => write!(
                f,
                "Function {function} references {operand} {value}, which cannot fit in the compact resolved instruction format"
            ),
        }
    }
}

impl std::error::Error for FunctionError {}

impl From<FunctionError> for String {
    fn from(error: FunctionError) -> Self {
        error.to_string()
    }
}

/// VM function definition
///
/// Represents a function defined in the VM's instruction set. These functions
/// are the primary unit of execution in the VM and can be called directly or
/// wrapped in closures.
///
/// VM functions support:
/// - Named parameters
/// - Upvalue capture for lexical scoping
/// - Nested function definitions
/// - Register-based execution
/// - Label-based control flow
#[derive(Clone)]
pub struct VMFunction {
    /// Optimized instructions with resolved indices
    resolved_instructions: Option<SmallVec<[ResolvedInstruction; 32]>>,
    /// Constant values extracted from instructions
    constant_values: Option<SmallVec<[Value; 16]>>,
    /// Function names referenced by resolved CALL instructions
    call_target_names: Option<SmallVec<[String; 16]>>,
    /// Function name (used for lookup and debugging)
    name: String,
    /// Parameter names (used for binding arguments)
    parameters: Vec<String>,
    /// Names of variables captured from outer scopes
    upvalues: Vec<String>,
    /// Parent function name (for nested functions)
    parent: Option<String>,
    /// Number of registers used by this function
    register_count: usize,
    /// List of instructions that make up the function body
    instructions: Vec<Instruction>,
    /// Mapping from label names to instruction indices
    labels: HashMap<String, usize>,
}

impl VMFunction {
    /// Create a new VM function with the specified parameters
    ///
    /// # Arguments
    /// * `name` - Function name used for lookup and debugging
    /// * `parameters` - List of parameter names
    /// * `upvalues` - List of variable names captured from outer scopes
    /// * `parent` - Optional parent function name (for nested functions)
    /// * `register_count` - Number of registers used by this function
    /// * `instructions` - List of instructions that make up the function body
    /// * `labels` - Mapping from label names to instruction indices
    pub fn new(
        name: String,
        parameters: Vec<String>,
        upvalues: Vec<String>,
        parent: Option<String>,
        register_count: usize,
        instructions: Vec<Instruction>,
        labels: HashMap<String, usize>,
    ) -> Self {
        VMFunction {
            resolved_instructions: None,
            constant_values: None,
            call_target_names: None,
            name,
            parameters,
            upvalues,
            parent,
            register_count,
            instructions,
            labels,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new_resolved_with_call_targets(
        name: String,
        parameters: Vec<String>,
        upvalues: Vec<String>,
        parent: Option<String>,
        mut register_count: usize,
        resolved_instructions: Vec<ResolvedInstruction>,
        constant_values: Vec<Value>,
        call_target_names: Vec<String>,
    ) -> FunctionResult<Self> {
        register_count = register_count
            .max(MIN_FRAME_REGISTER_COUNT)
            .max(parameters.len())
            .max(referenced_resolved_register_count(
                &name,
                &resolved_instructions,
            )?);

        if parameters.len() > register_count {
            return Err(FunctionError::ParametersExceedRegisters {
                function: name,
                parameters: parameters.len(),
                registers: register_count,
            });
        }

        Ok(Self {
            resolved_instructions: Some(SmallVec::from_vec(resolved_instructions)),
            constant_values: Some(SmallVec::from_vec(constant_values)),
            call_target_names: Some(SmallVec::from_vec(call_target_names)),
            name,
            parameters,
            upvalues,
            parent,
            register_count,
            instructions: Vec::new(),
            labels: HashMap::new(),
        })
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved_instructions.is_some()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn parameters(&self) -> &[String] {
        &self.parameters
    }

    pub fn upvalues(&self) -> &[String] {
        &self.upvalues
    }

    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    pub fn register_count(&self) -> usize {
        self.register_count
    }

    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    pub fn labels(&self) -> &HashMap<String, usize> {
        &self.labels
    }

    pub fn resolved_instructions(&self) -> Option<&[ResolvedInstruction]> {
        self.resolved_instructions.as_deref()
    }

    pub fn constant_values(&self) -> Option<&[Value]> {
        self.constant_values.as_deref()
    }

    pub fn call_target_names(&self) -> Option<&[String]> {
        self.call_target_names.as_deref()
    }

    pub fn take_resolved_parts(&mut self) -> Option<ResolvedFunctionParts> {
        Some((
            self.resolved_instructions.take()?,
            self.constant_values.take().unwrap_or_default(),
            self.call_target_names.take().unwrap_or_default(),
        ))
    }

    pub fn discard_resolved_instructions(&mut self) {
        self.resolved_instructions = None;
        self.constant_values = None;
        self.call_target_names = None;
    }

    /// Drop the source instruction stream after a runtime representation has
    /// been lowered.
    ///
    /// This is only valid for VM instances that do not need source instructions
    /// later, such as runs without instruction tracing hooks.
    pub fn discard_source_instructions(&mut self) {
        self.instructions.clear();
        self.instructions.shrink_to_fit();
        self.labels.clear();
        self.labels.shrink_to_fit();
    }

    /// Clone only executable metadata, omitting source instructions and labels.
    pub fn clone_without_source_instructions(&self) -> Self {
        Self {
            resolved_instructions: self.resolved_instructions.clone(),
            constant_values: self.constant_values.clone(),
            call_target_names: self.call_target_names.clone(),
            name: self.name.clone(),
            parameters: self.parameters.clone(),
            upvalues: self.upvalues.clone(),
            parent: self.parent.clone(),
            register_count: self.register_count,
            instructions: Vec::new(),
            labels: HashMap::new(),
        }
    }

    /// Number of register slots required by the instruction operands and ABI
    /// parameter/return placement.
    ///
    /// Compiled bytecode uses absolute physical register indices. Older
    /// compiler output can report a compact clear+secret register count even
    /// while using secret registers such as `r16`; this method derives the
    /// frame size the VM must actually allocate.
    pub fn try_frame_register_count(&self) -> FunctionResult<usize> {
        Ok(self
            .register_count
            .max(MIN_FRAME_REGISTER_COUNT)
            .max(self.parameters.len())
            .max(referenced_register_count(&self.name, &self.instructions)?))
    }

    /// Expand `register_count` to the frame size implied by the bytecode.
    pub fn try_normalize_register_count(&mut self) -> FunctionResult<()> {
        self.register_count = self.try_frame_register_count()?;
        Ok(())
    }

    /// Resolve symbolic instructions to optimized numeric form
    ///
    /// This process:
    /// 1. Collects instruction constants into a separate array
    /// 2. Resolves label references to instruction indices
    /// 3. Converts string-based function calls to index-based calls
    /// 4. Creates an optimized instruction set for faster execution
    ///
    /// The resolved instructions use numeric indices instead of strings,
    /// allowing for faster execution without string lookups.
    pub fn resolve_instructions(&mut self) -> FunctionResult<()> {
        if self.resolved_instructions.is_some() {
            return Ok(()); // Already resolved
        }

        self.try_normalize_register_count()?;

        let mut resolved = SmallVec::<[ResolvedInstruction; 32]>::new();
        let mut constants = SmallVec::<[Value; 16]>::new();
        let mut call_target_names = SmallVec::<[String; 16]>::new();

        if self.parameters.len() > self.register_count {
            return Err(FunctionError::ParametersExceedRegisters {
                function: self.name.clone(),
                parameters: self.parameters.len(),
                registers: self.register_count,
            });
        }

        // Resolve label references to instruction indices
        let mut label_indices = HashMap::new();
        for (label, &idx) in &self.labels {
            if idx > self.instructions.len() {
                return Err(FunctionError::LabelOutOfBounds {
                    function: self.name.clone(),
                    label: label.clone(),
                    target: idx,
                    instruction_count: self.instructions.len(),
                });
            }
            label_indices.insert(label.clone(), idx);
        }

        for (idx, instruction) in self.instructions.iter().enumerate() {
            validate_instruction_registers(&self.name, idx, instruction, self.register_count)?;
            match instruction {
                Instruction::NOP => {
                    resolved.push(ResolvedInstruction::NOP);
                }
                Instruction::LD(reg, offset) => {
                    resolved.push(ResolvedInstruction::LD(
                        resolved_operand(&self.name, "register", *reg)?,
                        *offset,
                    ));
                }
                Instruction::LDI(reg, value) => {
                    let const_idx = constants.len();
                    constants.push(value.clone());
                    resolved.push(ResolvedInstruction::LDI(
                        resolved_operand(&self.name, "register", *reg)?,
                        resolved_operand(&self.name, "constant index", const_idx)?,
                    ));
                }
                Instruction::MOV(dest, src) => {
                    resolved.push(ResolvedInstruction::MOV(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src)?,
                    ));
                }
                Instruction::ADD(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::ADD(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::SUB(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::SUB(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::MUL(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::MUL(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::DIV(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::DIV(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::MOD(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::MOD(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::AND(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::AND(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::OR(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::OR(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::XOR(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::XOR(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src1)?,
                        resolved_operand(&self.name, "register", *src2)?,
                    ));
                }
                Instruction::NOT(dest, src) => {
                    resolved.push(ResolvedInstruction::NOT(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src)?,
                    ));
                }
                Instruction::SHL(dest, src, amount) => {
                    resolved.push(ResolvedInstruction::SHL(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src)?,
                        resolved_operand(&self.name, "register", *amount)?,
                    ));
                }
                Instruction::SHR(dest, src, amount) => {
                    resolved.push(ResolvedInstruction::SHR(
                        resolved_operand(&self.name, "register", *dest)?,
                        resolved_operand(&self.name, "register", *src)?,
                        resolved_operand(&self.name, "register", *amount)?,
                    ));
                }
                Instruction::JMP(label) => {
                    let target = resolve_label(&self.name, &label_indices, label)?;
                    resolved.push(ResolvedInstruction::JMP(resolved_operand(
                        &self.name,
                        "jump target",
                        target,
                    )?));
                }
                Instruction::JMPEQ(label) => {
                    let target = resolve_label(&self.name, &label_indices, label)?;
                    resolved.push(ResolvedInstruction::JMPEQ(resolved_operand(
                        &self.name,
                        "jump target",
                        target,
                    )?));
                }
                Instruction::JMPNEQ(label) => {
                    let target = resolve_label(&self.name, &label_indices, label)?;
                    resolved.push(ResolvedInstruction::JMPNEQ(resolved_operand(
                        &self.name,
                        "jump target",
                        target,
                    )?));
                }
                Instruction::JMPLT(label) => {
                    let target = resolve_label(&self.name, &label_indices, label)?;
                    resolved.push(ResolvedInstruction::JMPLT(resolved_operand(
                        &self.name,
                        "jump target",
                        target,
                    )?));
                }
                Instruction::JMPGT(label) => {
                    let target = resolve_label(&self.name, &label_indices, label)?;
                    resolved.push(ResolvedInstruction::JMPGT(resolved_operand(
                        &self.name,
                        "jump target",
                        target,
                    )?));
                }
                Instruction::CALL(func_name) => {
                    let call_idx = call_target_names.len();
                    call_target_names.push(func_name.clone());
                    resolved.push(ResolvedInstruction::CALL(resolved_operand(
                        &self.name,
                        "call target index",
                        call_idx,
                    )?));
                }
                Instruction::RET(reg) => {
                    resolved.push(ResolvedInstruction::RET(resolved_operand(
                        &self.name, "register", *reg,
                    )?));
                }
                Instruction::PUSHARG(reg) => {
                    resolved.push(ResolvedInstruction::PUSHARG(resolved_operand(
                        &self.name, "register", *reg,
                    )?));
                }
                Instruction::CMP(reg1, reg2) => {
                    resolved.push(ResolvedInstruction::CMP(
                        resolved_operand(&self.name, "register", *reg1)?,
                        resolved_operand(&self.name, "register", *reg2)?,
                    ));
                }
                Instruction::LDS(reg, slot) => {
                    resolved.push(ResolvedInstruction::LDS(
                        resolved_operand(&self.name, "register", *reg)?,
                        resolved_operand(&self.name, "spill slot", *slot)?,
                    ));
                }
                Instruction::STS(slot, reg) => {
                    resolved.push(ResolvedInstruction::STS(
                        resolved_operand(&self.name, "spill slot", *slot)?,
                        resolved_operand(&self.name, "register", *reg)?,
                    ));
                }
            }
        }

        self.resolved_instructions = Some(resolved);
        self.constant_values = Some(constants);
        self.call_target_names = Some(call_target_names);
        Ok(())
    }
}

fn resolved_operand(
    function_name: &str,
    operand: &'static str,
    value: usize,
) -> FunctionResult<u32> {
    u32::try_from(value).map_err(|_| FunctionError::ResolvedOperandOverflow {
        function: function_name.to_owned(),
        operand,
        value,
    })
}

fn referenced_register_count(
    function_name: &str,
    instructions: &[Instruction],
) -> FunctionResult<usize> {
    instructions
        .iter()
        .filter_map(max_referenced_register)
        .max()
        .map_or(Ok(0), |max_register| {
            max_register
                .checked_add(1)
                .ok_or_else(|| FunctionError::RegisterIndexOverflow {
                    function: function_name.to_owned(),
                    register: max_register,
                })
        })
}

fn referenced_resolved_register_count(
    function_name: &str,
    instructions: &[ResolvedInstruction],
) -> FunctionResult<usize> {
    instructions
        .iter()
        .filter_map(max_referenced_resolved_register)
        .max()
        .map_or(Ok(0), |max_register| {
            max_register
                .checked_add(1)
                .ok_or_else(|| FunctionError::RegisterIndexOverflow {
                    function: function_name.to_owned(),
                    register: max_register,
                })
        })
}

fn max_referenced_register(instruction: &Instruction) -> Option<usize> {
    match instruction {
        Instruction::NOP => None,
        Instruction::LD(reg, _)
        | Instruction::LDI(reg, _)
        | Instruction::RET(reg)
        | Instruction::PUSHARG(reg)
        // For LDS/STS the slot is a spill-area index, not a register, so only the
        // register operand contributes to the register count.
        | Instruction::LDS(reg, _)
        | Instruction::STS(_, reg) => Some(*reg),
        Instruction::MOV(dest, src) | Instruction::NOT(dest, src) | Instruction::CMP(dest, src) => {
            Some((*dest).max(*src))
        }
        Instruction::ADD(dest, src1, src2)
        | Instruction::SUB(dest, src1, src2)
        | Instruction::MUL(dest, src1, src2)
        | Instruction::DIV(dest, src1, src2)
        | Instruction::MOD(dest, src1, src2)
        | Instruction::AND(dest, src1, src2)
        | Instruction::OR(dest, src1, src2)
        | Instruction::XOR(dest, src1, src2)
        | Instruction::SHL(dest, src1, src2)
        | Instruction::SHR(dest, src1, src2) => Some((*dest).max(*src1).max(*src2)),
        Instruction::JMP(_)
        | Instruction::JMPEQ(_)
        | Instruction::JMPNEQ(_)
        | Instruction::JMPLT(_)
        | Instruction::JMPGT(_)
        | Instruction::CALL(_) => None,
    }
}

fn max_referenced_resolved_register(instruction: &ResolvedInstruction) -> Option<usize> {
    match instruction {
        ResolvedInstruction::NOP => None,
        ResolvedInstruction::LD(reg, _)
        | ResolvedInstruction::LDI(reg, _)
        | ResolvedInstruction::RET(reg)
        | ResolvedInstruction::PUSHARG(reg)
        | ResolvedInstruction::LDS(reg, _)
        | ResolvedInstruction::STS(_, reg) => Some(*reg as usize),
        ResolvedInstruction::MOV(dest, src)
        | ResolvedInstruction::NOT(dest, src)
        | ResolvedInstruction::CMP(dest, src) => Some((*dest).max(*src) as usize),
        ResolvedInstruction::ADD(dest, src1, src2)
        | ResolvedInstruction::SUB(dest, src1, src2)
        | ResolvedInstruction::MUL(dest, src1, src2)
        | ResolvedInstruction::DIV(dest, src1, src2)
        | ResolvedInstruction::MOD(dest, src1, src2)
        | ResolvedInstruction::AND(dest, src1, src2)
        | ResolvedInstruction::OR(dest, src1, src2)
        | ResolvedInstruction::XOR(dest, src1, src2)
        | ResolvedInstruction::SHL(dest, src1, src2)
        | ResolvedInstruction::SHR(dest, src1, src2) => {
            Some((*dest).max(*src1).max(*src2) as usize)
        }
        ResolvedInstruction::JMP(_)
        | ResolvedInstruction::JMPEQ(_)
        | ResolvedInstruction::JMPNEQ(_)
        | ResolvedInstruction::JMPLT(_)
        | ResolvedInstruction::JMPGT(_)
        | ResolvedInstruction::CALL(_) => None,
    }
}

fn validate_instruction_registers(
    function_name: &str,
    instruction_index: usize,
    instruction: &Instruction,
    register_count: usize,
) -> FunctionResult<()> {
    match instruction {
        Instruction::NOP => {}
        Instruction::LD(dest, _)
        | Instruction::LDI(dest, _)
        | Instruction::RET(dest)
        | Instruction::PUSHARG(dest)
        | Instruction::LDS(dest, _)
        | Instruction::STS(_, dest) => {
            validate_register(function_name, instruction_index, *dest, register_count)?;
        }
        Instruction::MOV(dest, src) | Instruction::NOT(dest, src) | Instruction::CMP(dest, src) => {
            validate_register(function_name, instruction_index, *dest, register_count)?;
            validate_register(function_name, instruction_index, *src, register_count)?;
        }
        Instruction::ADD(dest, src1, src2)
        | Instruction::SUB(dest, src1, src2)
        | Instruction::MUL(dest, src1, src2)
        | Instruction::DIV(dest, src1, src2)
        | Instruction::MOD(dest, src1, src2)
        | Instruction::AND(dest, src1, src2)
        | Instruction::OR(dest, src1, src2)
        | Instruction::XOR(dest, src1, src2)
        | Instruction::SHL(dest, src1, src2)
        | Instruction::SHR(dest, src1, src2) => {
            validate_register(function_name, instruction_index, *dest, register_count)?;
            validate_register(function_name, instruction_index, *src1, register_count)?;
            validate_register(function_name, instruction_index, *src2, register_count)?;
        }
        Instruction::JMP(_)
        | Instruction::JMPEQ(_)
        | Instruction::JMPNEQ(_)
        | Instruction::JMPLT(_)
        | Instruction::JMPGT(_)
        | Instruction::CALL(_) => {}
    }

    Ok(())
}

fn validate_register(
    function_name: &str,
    instruction_index: usize,
    register: usize,
    register_count: usize,
) -> FunctionResult<()> {
    if register < register_count {
        return Ok(());
    }

    Err(FunctionError::RegisterOutOfBounds {
        function: function_name.to_owned(),
        instruction_index,
        register,
        register_count,
    })
}

fn resolve_label(
    function_name: &str,
    labels: &HashMap<String, usize>,
    label: &str,
) -> FunctionResult<usize> {
    labels
        .get(label)
        .copied()
        .ok_or_else(|| FunctionError::UnknownLabel {
            function: function_name.to_owned(),
            label: label.to_owned(),
        })
}

// Implement Hash manually to avoid issues with HashMap
impl Hash for VMFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.parameters.hash(state);
        self.upvalues.hash(state);
        self.parent.hash(state);
        self.register_count.hash(state);
        self.instructions.hash(state);
        // Skip hashing labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_types::Value;

    #[test]
    fn try_frame_register_count_reserves_return_register() {
        let mut function = VMFunction::new(
            "empty".to_string(),
            vec![],
            vec![],
            None,
            0,
            vec![],
            HashMap::new(),
        );

        assert_eq!(function.try_frame_register_count(), Ok(1));

        function.resolve_instructions().unwrap();

        assert_eq!(function.register_count(), 1);
    }

    #[test]
    fn try_frame_register_count_uses_absolute_secret_register_operands() {
        let function = VMFunction::new(
            "secret_frame".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![Instruction::LDI(16, Value::I64(7)), Instruction::RET(16)],
            HashMap::new(),
        );

        assert_eq!(function.try_frame_register_count(), Ok(17));
    }

    #[test]
    fn resolve_instructions_normalizes_register_count() {
        let mut function = VMFunction::new(
            "secret_frame".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![Instruction::LDI(16, Value::I64(7)), Instruction::RET(16)],
            HashMap::new(),
        );

        function.resolve_instructions().unwrap();

        assert_eq!(function.register_count(), 17);
    }

    #[test]
    fn resolve_instructions_assigns_constant_indices_during_lowering() {
        let mut function = VMFunction::new(
            "main".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![
                Instruction::LDI(0, Value::I64(1)),
                Instruction::CALL("native".to_string()),
                Instruction::LDI(1, Value::I64(2)),
                Instruction::RET(1),
            ],
            HashMap::new(),
        );

        function.resolve_instructions().unwrap();

        assert_eq!(
            function.constant_values(),
            Some(&[Value::I64(1), Value::I64(2)][..])
        );
        assert_eq!(
            function.call_target_names(),
            Some(&["native".to_string()][..])
        );
        let resolved = function
            .resolved_instructions()
            .expect("resolved instructions");
        assert!(matches!(resolved[0], ResolvedInstruction::LDI(0, 0)));
        assert!(matches!(resolved[1], ResolvedInstruction::CALL(0)));
        assert!(matches!(resolved[2], ResolvedInstruction::LDI(1, 1)));
    }

    #[test]
    fn try_frame_register_count_rejects_register_index_overflow() {
        let function = VMFunction::new(
            "overflow".to_string(),
            vec![],
            vec![],
            None,
            0,
            vec![Instruction::LDI(usize::MAX, Value::I64(7))],
            HashMap::new(),
        );

        let err = function.try_frame_register_count().unwrap_err();

        assert_eq!(
            err,
            FunctionError::RegisterIndexOverflow {
                function: "overflow".to_string(),
                register: usize::MAX
            }
        );
        assert_eq!(
            err.to_string(),
            format!(
                "Function overflow references register r{}, which cannot fit in a frame register count",
                usize::MAX
            )
        );
    }

    #[test]
    fn resolve_instructions_rejects_register_index_overflow() {
        let mut function = VMFunction::new(
            "overflow".to_string(),
            vec![],
            vec![],
            None,
            0,
            vec![Instruction::RET(usize::MAX)],
            HashMap::new(),
        );

        assert!(matches!(
            function.resolve_instructions(),
            Err(FunctionError::RegisterIndexOverflow {
                function,
                register: usize::MAX
            }) if function == "overflow"
        ));
    }

    #[test]
    fn resolve_instructions_reports_typed_unknown_label() {
        let mut function = VMFunction::new(
            "branch".to_string(),
            vec![],
            vec![],
            None,
            0,
            vec![Instruction::JMP("missing".to_string())],
            HashMap::new(),
        );

        let err = function.resolve_instructions().unwrap_err();

        assert_eq!(
            err,
            FunctionError::UnknownLabel {
                function: "branch".to_string(),
                label: "missing".to_string()
            }
        );
        assert_eq!(
            err.to_string(),
            "Function branch references unknown label 'missing'"
        );
    }

    #[test]
    fn resolve_instructions_reports_typed_label_out_of_bounds() {
        let mut labels = HashMap::new();
        labels.insert("past_end".to_string(), 2);
        let mut function = VMFunction::new(
            "branch".to_string(),
            vec![],
            vec![],
            None,
            0,
            vec![Instruction::JMP("past_end".to_string())],
            labels,
        );

        let err = function.resolve_instructions().unwrap_err();

        assert_eq!(
            err,
            FunctionError::LabelOutOfBounds {
                function: "branch".to_string(),
                label: "past_end".to_string(),
                target: 2,
                instruction_count: 1
            }
        );
        assert_eq!(
            err.to_string(),
            "Function branch label 'past_end' points past the instruction stream: 2 > 1"
        );
    }

    #[test]
    fn instruction_register_validation_reports_typed_bounds_error() {
        let err =
            validate_instruction_registers("math", 3, &Instruction::ADD(0, 1, 0), 1).unwrap_err();

        assert_eq!(
            err,
            FunctionError::RegisterOutOfBounds {
                function: "math".to_string(),
                instruction_index: 3,
                register: 1,
                register_count: 1
            }
        );
        assert_eq!(
            err.to_string(),
            "Function math instruction 3 references register r1 but only 1 registers are declared"
        );
    }
}
