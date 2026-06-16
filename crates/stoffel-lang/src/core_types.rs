use std::sync::Arc;

// Re-export types from stoffel_vm_types::core_types
pub use stoffel_vm_types::core_types::{
    ArrayRef, Closure, ForeignObjectRef, ObjectRef, ShareData, ShareType, Upvalue, Value, F64,
};

impl From<crate::bytecode::Constant> for Value {
    fn from(constant: crate::bytecode::Constant) -> Self {
        match constant {
            crate::bytecode::Constant::I64(i) => Value::I64(i),
            crate::bytecode::Constant::I32(i) => Value::I32(i),
            crate::bytecode::Constant::I16(i) => Value::I16(i),
            crate::bytecode::Constant::I8(i) => Value::I8(i),
            crate::bytecode::Constant::U8(i) => Value::U8(i),
            crate::bytecode::Constant::U16(i) => Value::U16(i),
            crate::bytecode::Constant::U32(i) => Value::U32(i),
            crate::bytecode::Constant::U64(i) => Value::U64(i),
            crate::bytecode::Constant::Float(f) => Value::Float(f),
            crate::bytecode::Constant::String(s) => Value::String(s),
            crate::bytecode::Constant::Bool(b) => Value::Bool(b),
            crate::bytecode::Constant::Object(id) => Value::from(ObjectRef::new(id)),
            crate::bytecode::Constant::Array(id) => Value::from(ArrayRef::new(id)),
            crate::bytecode::Constant::Foreign(id) => Value::from(ForeignObjectRef::new(id)),
            crate::bytecode::Constant::Closure(function_id, upvalues) => {
                // Create a new Closure with empty upvalues (they will be populated later)
                let closure = Closure::new(
                    function_id,
                    upvalues
                        .into_iter()
                        .map(|name| Upvalue::new(name, Value::Unit))
                        .collect(),
                );
                Value::Closure(Arc::new(closure))
            }
            crate::bytecode::Constant::Unit => Value::Unit,
            crate::bytecode::Constant::Share(share_type, data) => Value::Share(share_type, data),
        }
    }
}
