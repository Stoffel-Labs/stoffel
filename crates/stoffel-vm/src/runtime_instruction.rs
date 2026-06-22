use crate::error::{VmError, VmResult};
use std::collections::HashMap;
use std::sync::Arc;
use stoffel_vm_types::activations::{CompareFlag, InstructionPointer};
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::ResolvedInstruction;
use stoffel_vm_types::registers::{RegisterIndex, RETURN_REGISTER_INDEX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeBinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitAnd,
    BitOr,
    BitXor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeUnaryOp {
    BitNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeShiftOp {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeJumpCondition {
    Always,
    Equal,
    NotEqual,
    Less,
    Greater,
}

impl RuntimeJumpCondition {
    pub(crate) const fn should_jump(self, compare_flag: CompareFlag) -> bool {
        match self {
            Self::Always => true,
            Self::Equal => compare_flag.is_equal(),
            Self::NotEqual => compare_flag.is_not_equal(),
            Self::Less => compare_flag.is_less(),
            Self::Greater => compare_flag.is_greater(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RuntimeRegister(u32);

impl RuntimeRegister {
    pub(crate) fn try_new(register: usize, register_count: usize) -> VmResult<Self> {
        if register < register_count {
            Ok(Self(u32::try_from(register).map_err(|_| {
                VmError::RegisterOutOfBounds {
                    register,
                    register_count,
                }
            })?))
        } else {
            Err(VmError::RegisterOutOfBounds {
                register,
                register_count,
            })
        }
    }

    pub(crate) fn return_register(register_count: usize) -> VmResult<Self> {
        Self::try_new(RETURN_REGISTER_INDEX, register_count)
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }

    pub(crate) const fn register_index(self) -> RegisterIndex {
        RegisterIndex::new(self.index())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackOffset(i32);

impl StackOffset {
    pub(crate) const fn new(offset: i32) -> Self {
        Self(offset)
    }

    pub(crate) const fn raw(self) -> i32 {
        self.0
    }

    pub(crate) fn resolve_index(self, stack_len: usize) -> VmResult<usize> {
        if self.0 == 0 {
            return stack_len
                .checked_sub(1)
                .ok_or(VmError::StackAddressOutOfBounds { offset: self.0 });
        }

        let stack_len = i64::try_from(stack_len).map_err(|_| VmError::StackLengthOverflow)?;
        let index = stack_len
            .checked_add(i64::from(self.0))
            .and_then(|index| index.checked_sub(1))
            .ok_or(VmError::StackAddressOverflow { offset: self.0 })?;

        if index < 0 || index >= stack_len {
            return Err(VmError::StackAddressOutOfBounds { offset: self.0 });
        }

        usize::try_from(index).map_err(|_| VmError::StackAddressOutOfBounds { offset: self.0 })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JumpTarget(u32);

impl JumpTarget {
    pub(crate) fn try_new(target: usize, instruction_count: usize) -> VmResult<Self> {
        if target <= instruction_count {
            Ok(Self(u32::try_from(target).map_err(|_| {
                VmError::JumpTargetOutOfBounds {
                    target,
                    instruction_count,
                }
            })?))
        } else {
            Err(VmError::JumpTargetOutOfBounds {
                target,
                instruction_count,
            })
        }
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RuntimeConstant(u32);

impl RuntimeConstant {
    fn try_new(index: usize) -> VmResult<Self> {
        Ok(Self(
            u32::try_from(index).map_err(|_| VmError::ConstantOutOfBounds { index })?,
        ))
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RuntimeCallTarget(u32);

impl RuntimeCallTarget {
    fn try_new(index: usize) -> VmResult<Self> {
        Ok(Self(
            u32::try_from(index).map_err(|_| VmError::ConstantOutOfBounds { index })?,
        ))
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RuntimeImmediate {
    Constant(RuntimeConstant),
    #[cfg(test)]
    Inline(Box<Value>),
}

impl RuntimeImmediate {
    #[cfg(test)]
    pub(crate) fn inline(value: Value) -> Self {
        Self::Inline(Box::new(value))
    }

    pub(crate) fn direct_value(&self) -> VmResult<&Value> {
        match self {
            RuntimeImmediate::Constant(constant) => Err(VmError::ConstantOutOfBounds {
                index: constant.index(),
            }),
            #[cfg(test)]
            RuntimeImmediate::Inline(value) => Ok(value.as_ref()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RuntimeCall {
    Target(RuntimeCallTarget),
}

impl RuntimeCall {
    pub(crate) fn direct_function_name(&self) -> VmResult<&str> {
        match self {
            RuntimeCall::Target(target) => Err(VmError::ConstantOutOfBounds {
                index: target.index(),
            }),
        }
    }
}

#[derive(Debug)]
struct RuntimeInstructionEntry {
    instruction: PackedRuntimeInstruction,
}

#[derive(Debug, Clone)]
pub(crate) enum RuntimeInstruction {
    Noop,
    LoadStack {
        dest: RuntimeRegister,
        offset: StackOffset,
    },
    LoadImmediate {
        dest: RuntimeRegister,
        value: RuntimeImmediate,
    },
    Move {
        dest: RuntimeRegister,
        src: RuntimeRegister,
    },
    Binary {
        op: RuntimeBinaryOp,
        dest: RuntimeRegister,
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
    },
    Unary {
        op: RuntimeUnaryOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
    },
    Shift {
        op: RuntimeShiftOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        amount: RuntimeRegister,
    },
    Jump {
        condition: RuntimeJumpCondition,
        target: JumpTarget,
    },
    Call {
        function: RuntimeCall,
    },
    Return {
        src: RuntimeRegister,
    },
    PushArg {
        src: RuntimeRegister,
    },
    Compare {
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
    },
    SpillLoad {
        dest: RuntimeRegister,
        slot: usize,
    },
    SpillStore {
        slot: usize,
        src: RuntimeRegister,
    },
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeOpcode {
    Noop,
    LoadStack,
    LoadImmediate,
    Move,
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitAnd,
    BitOr,
    BitXor,
    BitNot,
    ShiftLeft,
    ShiftRight,
    Jump,
    JumpEqual,
    JumpNotEqual,
    JumpLess,
    JumpGreater,
    Call,
    Return,
    PushArg,
    Compare,
    SpillLoad,
    SpillStore,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PackedRuntimeInstruction([u8; 13]);

impl PackedRuntimeInstruction {
    fn new(opcode: RuntimeOpcode, a: u32, b: u32, c: u32) -> Self {
        let mut bytes = [0; 13];
        bytes[0] = opcode as u8;
        bytes[1..5].copy_from_slice(&a.to_le_bytes());
        bytes[5..9].copy_from_slice(&b.to_le_bytes());
        bytes[9..13].copy_from_slice(&c.to_le_bytes());
        Self(bytes)
    }

    fn decode(self) -> RuntimeInstruction {
        let opcode = RuntimeOpcode::from_u8(self.0[0]);
        let a = self.operand(1);
        let b = self.operand(5);
        let c = self.operand(9);

        match opcode {
            RuntimeOpcode::Noop => RuntimeInstruction::Noop,
            RuntimeOpcode::LoadStack => RuntimeInstruction::LoadStack {
                dest: RuntimeRegister(a),
                offset: StackOffset::new(b as i32),
            },
            RuntimeOpcode::LoadImmediate => RuntimeInstruction::LoadImmediate {
                dest: RuntimeRegister(a),
                value: RuntimeImmediate::Constant(RuntimeConstant(b)),
            },
            RuntimeOpcode::Move => RuntimeInstruction::Move {
                dest: RuntimeRegister(a),
                src: RuntimeRegister(b),
            },
            RuntimeOpcode::Add => binary(RuntimeBinaryOp::Add, a, b, c),
            RuntimeOpcode::Subtract => binary(RuntimeBinaryOp::Subtract, a, b, c),
            RuntimeOpcode::Multiply => binary(RuntimeBinaryOp::Multiply, a, b, c),
            RuntimeOpcode::Divide => binary(RuntimeBinaryOp::Divide, a, b, c),
            RuntimeOpcode::Modulo => binary(RuntimeBinaryOp::Modulo, a, b, c),
            RuntimeOpcode::BitAnd => binary(RuntimeBinaryOp::BitAnd, a, b, c),
            RuntimeOpcode::BitOr => binary(RuntimeBinaryOp::BitOr, a, b, c),
            RuntimeOpcode::BitXor => binary(RuntimeBinaryOp::BitXor, a, b, c),
            RuntimeOpcode::BitNot => RuntimeInstruction::Unary {
                op: RuntimeUnaryOp::BitNot,
                dest: RuntimeRegister(a),
                src: RuntimeRegister(b),
            },
            RuntimeOpcode::ShiftLeft => shift(RuntimeShiftOp::Left, a, b, c),
            RuntimeOpcode::ShiftRight => shift(RuntimeShiftOp::Right, a, b, c),
            RuntimeOpcode::Jump => jump(RuntimeJumpCondition::Always, a),
            RuntimeOpcode::JumpEqual => jump(RuntimeJumpCondition::Equal, a),
            RuntimeOpcode::JumpNotEqual => jump(RuntimeJumpCondition::NotEqual, a),
            RuntimeOpcode::JumpLess => jump(RuntimeJumpCondition::Less, a),
            RuntimeOpcode::JumpGreater => jump(RuntimeJumpCondition::Greater, a),
            RuntimeOpcode::Call => RuntimeInstruction::Call {
                function: RuntimeCall::Target(RuntimeCallTarget(a)),
            },
            RuntimeOpcode::Return => RuntimeInstruction::Return {
                src: RuntimeRegister(a),
            },
            RuntimeOpcode::PushArg => RuntimeInstruction::PushArg {
                src: RuntimeRegister(a),
            },
            RuntimeOpcode::Compare => RuntimeInstruction::Compare {
                lhs: RuntimeRegister(a),
                rhs: RuntimeRegister(b),
            },
            RuntimeOpcode::SpillLoad => RuntimeInstruction::SpillLoad {
                dest: RuntimeRegister(a),
                slot: b as usize,
            },
            RuntimeOpcode::SpillStore => RuntimeInstruction::SpillStore {
                slot: a as usize,
                src: RuntimeRegister(b),
            },
        }
    }

    fn operand(self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.0[offset],
            self.0[offset + 1],
            self.0[offset + 2],
            self.0[offset + 3],
        ])
    }
}

impl std::fmt::Debug for PackedRuntimeInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PackedRuntimeInstruction")
            .field(&self.decode())
            .finish()
    }
}

impl RuntimeOpcode {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Noop,
            1 => Self::LoadStack,
            2 => Self::LoadImmediate,
            3 => Self::Move,
            4 => Self::Add,
            5 => Self::Subtract,
            6 => Self::Multiply,
            7 => Self::Divide,
            8 => Self::Modulo,
            9 => Self::BitAnd,
            10 => Self::BitOr,
            11 => Self::BitXor,
            12 => Self::BitNot,
            13 => Self::ShiftLeft,
            14 => Self::ShiftRight,
            15 => Self::Jump,
            16 => Self::JumpEqual,
            17 => Self::JumpNotEqual,
            18 => Self::JumpLess,
            19 => Self::JumpGreater,
            20 => Self::Call,
            21 => Self::Return,
            22 => Self::PushArg,
            23 => Self::Compare,
            24 => Self::SpillLoad,
            25 => Self::SpillStore,
            _ => unreachable!("runtime opcode is only created by RuntimeOpcode"),
        }
    }
}

fn binary(op: RuntimeBinaryOp, dest: u32, lhs: u32, rhs: u32) -> RuntimeInstruction {
    RuntimeInstruction::Binary {
        op,
        dest: RuntimeRegister(dest),
        lhs: RuntimeRegister(lhs),
        rhs: RuntimeRegister(rhs),
    }
}

fn shift(op: RuntimeShiftOp, dest: u32, src: u32, amount: u32) -> RuntimeInstruction {
    RuntimeInstruction::Shift {
        op,
        dest: RuntimeRegister(dest),
        src: RuntimeRegister(src),
        amount: RuntimeRegister(amount),
    }
}

fn jump(condition: RuntimeJumpCondition, target: u32) -> RuntimeInstruction {
    RuntimeInstruction::Jump {
        condition,
        target: JumpTarget(target),
    }
}

/// VM function lowered for runtime dispatch.
///
/// `VMFunction` keeps source-oriented metadata for registration, binary
/// conversion, hook display, and call-frame setup. This type stores only the
/// execution form the VM actually dispatches, so constants and symbolic calls
/// are lowered once at registration instead of being re-decoded for every
/// instruction fetch.
#[derive(Debug)]
pub(crate) struct RuntimeFunction {
    instructions: Vec<RuntimeInstructionEntry>,
    constants: Box<[Value]>,
    call_targets: Box<[Arc<str>]>,
}

impl RuntimeFunction {
    pub(crate) fn from_vm_function(function: &VMFunction) -> VmResult<Self> {
        let resolved_instructions = function.resolved_instructions().ok_or_else(|| {
            VmError::MissingResolvedInstructions {
                function: function.name().to_owned(),
            }
        })?;
        let instruction_count = resolved_instructions.len();
        if !function.instructions().is_empty() && instruction_count != function.instructions().len()
        {
            return Err(VmError::RuntimeInstructionMetadataMismatch {
                function: function.name().to_owned(),
                resolved_instruction_count: instruction_count,
                source_instruction_count: function.instructions().len(),
            });
        }

        let mut constants = RuntimeConstantInterner::default();
        let mut call_targets = RuntimeCallTargetInterner::default();
        let mut instructions = Vec::with_capacity(resolved_instructions.len());
        for resolved in resolved_instructions {
            instructions.push(RuntimeInstructionEntry {
                instruction: lower_instruction_from_parts(
                    function.register_count(),
                    function.constant_values(),
                    function.call_target_names(),
                    resolved,
                    instruction_count,
                    &mut constants,
                    &mut call_targets,
                )?,
            });
        }

        Ok(Self {
            instructions,
            constants: constants.into_values(),
            call_targets: call_targets.into_values(),
        })
    }

    pub(crate) fn from_vm_function_consuming_resolved(function: &mut VMFunction) -> VmResult<Self> {
        let function_name = function.name().to_owned();
        let source_instruction_count = function.instructions().len();
        let register_count = function.register_count();
        let (resolved_instructions, constant_values, call_target_names) = function
            .take_resolved_parts()
            .ok_or(VmError::MissingResolvedInstructions {
                function: function_name.clone(),
            })?;
        let instruction_count = resolved_instructions.len();
        if source_instruction_count != 0 && instruction_count != source_instruction_count {
            return Err(VmError::RuntimeInstructionMetadataMismatch {
                function: function_name,
                resolved_instruction_count: instruction_count,
                source_instruction_count,
            });
        }

        let mut constants = RuntimeConstantInterner::default();
        let mut call_targets = RuntimeCallTargetInterner::default();
        let mut instructions = Vec::with_capacity(instruction_count);
        for resolved in resolved_instructions.iter() {
            instructions.push(RuntimeInstructionEntry {
                instruction: lower_instruction_from_parts(
                    register_count,
                    Some(&constant_values),
                    Some(&call_target_names),
                    resolved,
                    instruction_count,
                    &mut constants,
                    &mut call_targets,
                )?,
            });
        }

        Ok(Self {
            instructions,
            constants: constants.into_values(),
            call_targets: call_targets.into_values(),
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.instructions.len()
    }

    #[inline]
    pub(crate) fn get_instruction(
        &self,
        instruction_pointer: InstructionPointer,
    ) -> Option<FetchedInstruction<'_>> {
        self.instructions
            .get(instruction_pointer.index())
            .map(|entry| FetchedInstruction {
                function: self,
                entry,
            })
    }

    #[cfg(test)]
    fn instruction_entry(
        &self,
        instruction_pointer: InstructionPointer,
    ) -> VmResult<&RuntimeInstructionEntry> {
        let index = instruction_pointer.index();
        self.instructions
            .get(index)
            .ok_or(VmError::InstructionOutOfBounds { index })
    }

    fn constant(&self, constant: RuntimeConstant) -> VmResult<&Value> {
        self.constants
            .get(constant.index())
            .ok_or(VmError::ConstantOutOfBounds {
                index: constant.index(),
            })
    }

    fn call_target(&self, target: RuntimeCallTarget) -> VmResult<&str> {
        self.call_targets
            .get(target.index())
            .map(|target| target.as_ref())
            .ok_or(VmError::ConstantOutOfBounds {
                index: target.index(),
            })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FetchedInstruction<'function> {
    function: &'function RuntimeFunction,
    entry: &'function RuntimeInstructionEntry,
}

impl<'function> FetchedInstruction<'function> {
    #[cfg(test)]
    pub(crate) fn fetch(
        instruction_pointer: InstructionPointer,
        function: &'function RuntimeFunction,
    ) -> VmResult<Self> {
        let entry = function.instruction_entry(instruction_pointer)?;
        Ok(FetchedInstruction { function, entry })
    }

    #[inline]
    pub(crate) fn runtime_instruction(&self) -> RuntimeInstruction {
        self.entry.instruction.decode()
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn runtime_instruction_for_test(&self) -> RuntimeInstruction {
        self.runtime_instruction()
    }

    #[inline]
    pub(crate) fn load_immediate_value(
        self,
        value: &'function RuntimeImmediate,
    ) -> VmResult<&'function Value> {
        match value {
            RuntimeImmediate::Constant(constant) => self.function.constant(*constant),
            #[cfg(test)]
            RuntimeImmediate::Inline(value) => Ok(value.as_ref()),
        }
    }

    #[inline]
    pub(crate) fn call_target_name(
        self,
        function: &'function RuntimeCall,
    ) -> VmResult<&'function str> {
        match function {
            RuntimeCall::Target(target) => self.function.call_target(*target),
        }
    }
}

#[derive(Default)]
struct RuntimeConstantInterner {
    index: HashMap<Value, RuntimeConstant>,
    values: Vec<Value>,
}

impl RuntimeConstantInterner {
    fn intern(&mut self, value: Value) -> VmResult<RuntimeConstant> {
        if let Some(existing) = self.index.get(&value) {
            return Ok(*existing);
        }

        let constant = RuntimeConstant::try_new(self.values.len())?;
        self.values.push(value.clone());
        self.index.insert(value, constant);
        Ok(constant)
    }

    fn into_values(self) -> Box<[Value]> {
        self.values.into_boxed_slice()
    }
}

#[derive(Default)]
struct RuntimeCallTargetInterner {
    index: HashMap<String, RuntimeCallTarget>,
    values: Vec<Arc<str>>,
}

impl RuntimeCallTargetInterner {
    fn intern(&mut self, name: &str) -> VmResult<RuntimeCallTarget> {
        if let Some(existing) = self.index.get(name) {
            return Ok(*existing);
        }

        let target = RuntimeCallTarget::try_new(self.values.len())?;
        let value = Arc::<str>::from(name);
        self.values.push(value);
        self.index.insert(name.to_owned(), target);
        Ok(target)
    }

    fn into_values(self) -> Box<[Arc<str>]> {
        self.values.into_boxed_slice()
    }
}

fn lower_instruction_from_parts(
    register_count: usize,
    constant_values: Option<&[Value]>,
    call_target_names: Option<&[String]>,
    resolved: &ResolvedInstruction,
    instruction_count: usize,
    constants: &mut RuntimeConstantInterner,
    call_targets: &mut RuntimeCallTargetInterner,
) -> VmResult<PackedRuntimeInstruction> {
    Ok(match *resolved {
        ResolvedInstruction::NOP => PackedRuntimeInstruction::new(RuntimeOpcode::Noop, 0, 0, 0),
        ResolvedInstruction::LD(dest, offset) => PackedRuntimeInstruction::new(
            RuntimeOpcode::LoadStack,
            reg(register_count, dest)?.raw(),
            offset as u32,
            0,
        ),
        ResolvedInstruction::LDI(dest, const_idx) => {
            let value = get_constant_value(constant_values, const_idx)?;
            let constant = constants.intern(value)?;
            PackedRuntimeInstruction::new(
                RuntimeOpcode::LoadImmediate,
                reg(register_count, dest)?.raw(),
                constant.raw(),
                0,
            )
        }
        ResolvedInstruction::MOV(dest, src) => {
            pack2(RuntimeOpcode::Move, register_count, dest, src)?
        }
        ResolvedInstruction::ADD(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::Add, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::SUB(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::Subtract, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::MUL(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::Multiply, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::DIV(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::Divide, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::MOD(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::Modulo, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::AND(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::BitAnd, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::OR(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::BitOr, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::XOR(dest, lhs, rhs) => {
            pack3(RuntimeOpcode::BitXor, register_count, dest, lhs, rhs)?
        }
        ResolvedInstruction::NOT(dest, src) => {
            pack2(RuntimeOpcode::BitNot, register_count, dest, src)?
        }
        ResolvedInstruction::SHL(dest, src, amount) => {
            pack3(RuntimeOpcode::ShiftLeft, register_count, dest, src, amount)?
        }
        ResolvedInstruction::SHR(dest, src, amount) => {
            pack3(RuntimeOpcode::ShiftRight, register_count, dest, src, amount)?
        }
        ResolvedInstruction::JMP(target) => {
            lower_jump(RuntimeJumpCondition::Always, target, instruction_count)?
        }
        ResolvedInstruction::JMPEQ(target) => {
            lower_jump(RuntimeJumpCondition::Equal, target, instruction_count)?
        }
        ResolvedInstruction::JMPNEQ(target) => {
            lower_jump(RuntimeJumpCondition::NotEqual, target, instruction_count)?
        }
        ResolvedInstruction::JMPLT(target) => {
            lower_jump(RuntimeJumpCondition::Less, target, instruction_count)?
        }
        ResolvedInstruction::JMPGT(target) => {
            lower_jump(RuntimeJumpCondition::Greater, target, instruction_count)?
        }
        ResolvedInstruction::CALL(func_idx) => {
            let func_name = get_function_name(constant_values, call_target_names, func_idx)?;
            let target = call_targets.intern(func_name)?;
            PackedRuntimeInstruction::new(RuntimeOpcode::Call, target.raw(), 0, 0)
        }
        ResolvedInstruction::RET(src) => PackedRuntimeInstruction::new(
            RuntimeOpcode::Return,
            reg(register_count, src)?.raw(),
            0,
            0,
        ),
        ResolvedInstruction::PUSHARG(src) => PackedRuntimeInstruction::new(
            RuntimeOpcode::PushArg,
            reg(register_count, src)?.raw(),
            0,
            0,
        ),
        ResolvedInstruction::CMP(lhs, rhs) => PackedRuntimeInstruction::new(
            RuntimeOpcode::Compare,
            reg(register_count, lhs)?.raw(),
            reg(register_count, rhs)?.raw(),
            0,
        ),
        ResolvedInstruction::LDS(dest, slot) => PackedRuntimeInstruction::new(
            RuntimeOpcode::SpillLoad,
            reg(register_count, dest)?.raw(),
            u32::try_from(slot).map_err(|_| VmError::ConstantOutOfBounds { index: slot })?,
            0,
        ),
        ResolvedInstruction::STS(slot, src) => PackedRuntimeInstruction::new(
            RuntimeOpcode::SpillStore,
            u32::try_from(slot).map_err(|_| VmError::ConstantOutOfBounds { index: slot })?,
            reg(register_count, src)?.raw(),
            0,
        ),
    })
}

fn pack2(
    opcode: RuntimeOpcode,
    register_count: usize,
    a: usize,
    b: usize,
) -> VmResult<PackedRuntimeInstruction> {
    Ok(PackedRuntimeInstruction::new(
        opcode,
        reg(register_count, a)?.raw(),
        reg(register_count, b)?.raw(),
        0,
    ))
}

fn pack3(
    opcode: RuntimeOpcode,
    register_count: usize,
    a: usize,
    b: usize,
    c: usize,
) -> VmResult<PackedRuntimeInstruction> {
    Ok(PackedRuntimeInstruction::new(
        opcode,
        reg(register_count, a)?.raw(),
        reg(register_count, b)?.raw(),
        reg(register_count, c)?.raw(),
    ))
}

impl RuntimeRegister {
    const fn raw(self) -> u32 {
        self.0
    }
}

impl RuntimeConstant {
    const fn raw(self) -> u32 {
        self.0
    }
}

impl RuntimeCallTarget {
    const fn raw(self) -> u32 {
        self.0
    }
}

impl JumpTarget {
    const fn raw(self) -> u32 {
        self.0
    }
}

fn jump_opcode(condition: RuntimeJumpCondition) -> RuntimeOpcode {
    match condition {
        RuntimeJumpCondition::Always => RuntimeOpcode::Jump,
        RuntimeJumpCondition::Equal => RuntimeOpcode::JumpEqual,
        RuntimeJumpCondition::NotEqual => RuntimeOpcode::JumpNotEqual,
        RuntimeJumpCondition::Less => RuntimeOpcode::JumpLess,
        RuntimeJumpCondition::Greater => RuntimeOpcode::JumpGreater,
    }
}

fn reg(register_count: usize, register: usize) -> VmResult<RuntimeRegister> {
    RuntimeRegister::try_new(register, register_count)
}

fn lower_jump(
    condition: RuntimeJumpCondition,
    target: usize,
    instruction_count: usize,
) -> VmResult<PackedRuntimeInstruction> {
    Ok(PackedRuntimeInstruction::new(
        jump_opcode(condition),
        JumpTarget::try_new(target, instruction_count)?.raw(),
        0,
        0,
    ))
}

fn get_constant_value(constants: Option<&[Value]>, const_idx: usize) -> VmResult<Value> {
    get_constant_value_ref(constants, const_idx).cloned()
}

fn get_constant_value_ref(constants: Option<&[Value]>, const_idx: usize) -> VmResult<&Value> {
    constants
        .and_then(|constants| constants.get(const_idx))
        .ok_or(VmError::ConstantOutOfBounds { index: const_idx })
}

fn get_function_name<'a>(
    constants: Option<&'a [Value]>,
    call_target_names: Option<&'a [String]>,
    func_idx: usize,
) -> VmResult<&'a str> {
    if let Some(name) = call_target_names.and_then(|names| names.get(func_idx)) {
        return Ok(name);
    }

    get_function_name_from_constant(constants, func_idx)
}

fn get_function_name_from_constant(constants: Option<&[Value]>, func_idx: usize) -> VmResult<&str> {
    let value = get_constant_value_ref(constants, func_idx)?;
    match value {
        Value::String(name) => Ok(name.as_str()),
        _ => Err(VmError::InvalidFunctionNameConstant { index: func_idx }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::mem::size_of;
    use stoffel_vm_types::instructions::Instruction;

    #[test]
    fn stack_offset_resolves_relative_to_top_of_stack() {
        assert_eq!(StackOffset::new(0).resolve_index(3).unwrap(), 2);
        assert_eq!(StackOffset::new(-1).resolve_index(3).unwrap(), 1);
        assert_eq!(StackOffset::new(-2).resolve_index(3).unwrap(), 0);
    }

    #[test]
    fn packed_runtime_instruction_stays_byte_dense() {
        assert_eq!(size_of::<PackedRuntimeInstruction>(), 13);
    }

    #[test]
    fn stack_offset_rejects_addresses_outside_stack() {
        assert!(matches!(
            StackOffset::new(0).resolve_index(0),
            Err(VmError::StackAddressOutOfBounds { offset: 0 })
        ));
        assert!(matches!(
            StackOffset::new(1).resolve_index(1),
            Err(VmError::StackAddressOutOfBounds { offset: 1 })
        ));
        assert!(matches!(
            StackOffset::new(-3).resolve_index(2),
            Err(VmError::StackAddressOutOfBounds { offset: -3 })
        ));
    }

    #[test]
    fn jump_condition_evaluates_compare_flags_in_one_place() {
        assert!(RuntimeJumpCondition::Always.should_jump(CompareFlag::Less));
        assert!(RuntimeJumpCondition::Equal.should_jump(CompareFlag::Equal));
        assert!(!RuntimeJumpCondition::Equal.should_jump(CompareFlag::Greater));
        assert!(RuntimeJumpCondition::NotEqual.should_jump(CompareFlag::Less));
        assert!(!RuntimeJumpCondition::NotEqual.should_jump(CompareFlag::Equal));
        assert!(RuntimeJumpCondition::Less.should_jump(CompareFlag::Less));
        assert!(!RuntimeJumpCondition::Less.should_jump(CompareFlag::Greater));
        assert!(RuntimeJumpCondition::Greater.should_jump(CompareFlag::Greater));
        assert!(!RuntimeJumpCondition::Greater.should_jump(CompareFlag::Less));
    }

    #[test]
    fn runtime_register_accepts_operands_inside_frame() {
        assert_eq!(RuntimeRegister::try_new(0, 3).unwrap().index(), 0);
        assert_eq!(RuntimeRegister::try_new(2, 3).unwrap().index(), 2);
    }

    #[test]
    fn runtime_register_rejects_operands_outside_frame() {
        assert!(matches!(
            RuntimeRegister::try_new(3, 3),
            Err(VmError::RegisterOutOfBounds {
                register: 3,
                register_count: 3
            })
        ));
    }

    #[test]
    fn lowering_preserves_noop_as_dispatch_only_instruction() {
        let function = VMFunction::new(
            "noop".to_owned(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::NOP],
            HashMap::new(),
        );

        assert!(matches!(
            lower_instruction_from_parts(
                function.register_count(),
                function.constant_values(),
                function.call_target_names(),
                &ResolvedInstruction::NOP,
                1,
                &mut RuntimeConstantInterner::default(),
                &mut RuntimeCallTargetInterner::default(),
            )
            .unwrap()
            .decode(),
            RuntimeInstruction::Noop
        ));
    }

    #[test]
    fn lowering_rejects_resolved_register_outside_frame() {
        let function = VMFunction::new(
            "bad_register".to_owned(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::RET(0)],
            HashMap::new(),
        );

        let error = lower_instruction_from_parts(
            function.register_count(),
            function.constant_values(),
            function.call_target_names(),
            &ResolvedInstruction::RET(1),
            1,
            &mut RuntimeConstantInterner::default(),
            &mut RuntimeCallTargetInterner::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            VmError::RegisterOutOfBounds {
                register: 1,
                register_count: 1
            }
        ));
    }

    #[test]
    fn jump_target_accepts_instruction_indices_and_function_end() {
        assert_eq!(JumpTarget::try_new(0, 3).unwrap().index(), 0);
        assert_eq!(JumpTarget::try_new(2, 3).unwrap().index(), 2);
        assert_eq!(JumpTarget::try_new(3, 3).unwrap().index(), 3);
    }

    #[test]
    fn jump_target_rejects_targets_past_function_end() {
        assert!(matches!(
            JumpTarget::try_new(4, 3),
            Err(VmError::JumpTargetOutOfBounds {
                target: 4,
                instruction_count: 3
            })
        ));
    }

    #[test]
    fn lowering_rejects_resolved_jump_target_past_function_end() {
        let function = VMFunction::new(
            "bad_jump".to_owned(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::RET(0)],
            HashMap::new(),
        );

        let error = lower_instruction_from_parts(
            function.register_count(),
            function.constant_values(),
            function.call_target_names(),
            &ResolvedInstruction::JMP(2),
            1,
            &mut RuntimeConstantInterner::default(),
            &mut RuntimeCallTargetInterner::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            VmError::JumpTargetOutOfBounds {
                target: 2,
                instruction_count: 1
            }
        ));
    }
}
