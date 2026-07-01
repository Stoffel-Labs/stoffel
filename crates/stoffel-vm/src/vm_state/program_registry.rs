use super::VMState;
use crate::error::VmResult;
use crate::foreign_functions::{ForeignFunction, Function};
use std::sync::Arc;
use stoffel_vm_types::functions::ResolvedFunctionHeader;
use stoffel_vm_types::instructions::ResolvedInstructionInput;

impl VMState {
    pub(crate) fn try_insert_function(&mut self, function: Function) -> VmResult<()> {
        self.program.try_insert(function)?;
        self.last_call_target = None;
        Ok(())
    }

    pub(crate) fn try_insert_function_without_vm_source(
        &mut self,
        function: Function,
    ) -> VmResult<()> {
        self.program.try_insert_without_vm_source(function)?;
        self.last_call_target = None;
        Ok(())
    }

    pub(crate) fn try_insert_resolved_function_without_vm_source(
        &mut self,
        header: ResolvedFunctionHeader,
        next_instruction: impl FnMut() -> Option<ResolvedInstructionInput>,
    ) -> VmResult<()> {
        self.program
            .try_insert_resolved_without_vm_source(header, next_instruction)?;
        self.last_call_target = None;
        Ok(())
    }

    pub(crate) fn try_insert_method(
        &mut self,
        receiver_type: &str,
        method_name: &str,
        function: Function,
    ) -> VmResult<()> {
        self.program
            .try_insert_method(receiver_type, method_name, function)?;
        self.last_call_target = None;
        Ok(())
    }

    pub(crate) fn has_function(&self, name: &str) -> bool {
        self.program.contains(name)
    }

    pub(crate) fn ensure_function_names_available(
        &self,
        names: &[&str],
        group_name: &str,
    ) -> VmResult<()> {
        self.program.ensure_names_available(names, group_name)
    }

    pub(crate) fn discard_vm_source_instructions(&mut self) {
        self.program.discard_vm_source_instructions();
    }

    pub(crate) fn foreign_function(
        &self,
        function_name: &str,
    ) -> VmResult<Option<Arc<ForeignFunction>>> {
        self.program.foreign_function(function_name)
    }
}
