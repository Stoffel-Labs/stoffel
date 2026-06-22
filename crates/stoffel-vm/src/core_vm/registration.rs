use super::VirtualMachine;
use crate::foreign_functions::{
    ForeignFunction, ForeignFunctionCallbackError, ForeignFunctionCallbackResult,
    ForeignFunctionContext, Function, MpcOnlineBuiltin,
};
use crate::{error::VmError, VirtualMachineResult};
use parking_lot::Mutex;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ForeignObjectRef, Value};
use stoffel_vm_types::functions::VMFunction;

impl VirtualMachine {
    pub fn try_register_standard_library(&mut self) -> VirtualMachineResult<()> {
        self.ensure_function_names_available(
            crate::standard_library::FUNCTION_NAMES,
            "standard library",
        )?;
        crate::standard_library::register(self)
    }

    #[track_caller]
    pub fn register_standard_library(&mut self) {
        self.try_register_standard_library()
            .expect("invalid standard library registration");
    }

    pub fn try_register_mpc_builtins(&mut self) -> VirtualMachineResult<()> {
        crate::mpc_builtins::try_register_mpc_builtins(self)
    }

    #[track_caller]
    pub fn register_mpc_builtins(&mut self) {
        self.try_register_mpc_builtins()
            .expect("invalid MPC builtin registration");
    }

    pub fn has_function(&self, name: &str) -> bool {
        self.state.has_function(name)
    }

    pub(crate) fn ensure_function_names_available(
        &self,
        names: &[&str],
        group_name: &str,
    ) -> Result<(), VmError> {
        self.state
            .ensure_function_names_available(names, group_name)
    }

    /// Release VM source instruction streams after registration.
    ///
    /// The lowered runtime instructions remain executable. Call this only when
    /// no instruction hooks will be registered later, because those hook events
    /// need the original source instructions.
    pub fn discard_vm_source_instructions(&mut self) {
        self.state.discard_vm_source_instructions();
    }

    /// Register a VM function.
    pub fn try_register_function(&mut self, function: VMFunction) -> VirtualMachineResult<()> {
        Ok(self.state.try_insert_function(Function::vm(function))?)
    }

    /// Register a VM function without retaining its source instruction stream.
    ///
    /// The lowered runtime instructions remain executable, but instruction
    /// hooks cannot inspect source instructions for this function afterward.
    pub fn try_register_function_without_source(
        &mut self,
        function: VMFunction,
    ) -> VirtualMachineResult<()> {
        Ok(self
            .state
            .try_insert_function_without_vm_source(Function::vm(function))?)
    }

    #[track_caller]
    pub fn register_function(&mut self, function: VMFunction) {
        self.try_register_function(function)
            .expect("invalid VM function registration");
    }

    /// Register a foreign function.
    pub fn try_register_foreign_function<F>(
        &mut self,
        name: &str,
        func: F,
    ) -> VirtualMachineResult<()>
    where
        F: Fn(ForeignFunctionContext) -> Result<Value, String> + 'static + Send + Sync,
    {
        self.try_register_typed_foreign_function(name, move |ctx| {
            func(ctx).map_err(ForeignFunctionCallbackError::from)
        })
    }

    pub fn try_register_typed_foreign_function<F>(
        &mut self,
        name: &str,
        func: F,
    ) -> VirtualMachineResult<()>
    where
        F: Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value>
            + 'static
            + Send
            + Sync,
    {
        Ok(self
            .state
            .try_insert_function(Function::foreign(ForeignFunction::new(
                name,
                Arc::new(func),
            )))?)
    }

    pub fn try_register_typed_foreign_method<F>(
        &mut self,
        receiver_type: &str,
        method_name: &str,
        canonical_name: &str,
        func: F,
    ) -> VirtualMachineResult<()>
    where
        F: Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value>
            + 'static
            + Send
            + Sync,
    {
        Ok(self.state.try_insert_method(
            receiver_type,
            method_name,
            Function::foreign(ForeignFunction::new(canonical_name, Arc::new(func))),
        )?)
    }

    pub(crate) fn try_register_mpc_online_foreign_function<F>(
        &mut self,
        builtin: MpcOnlineBuiltin,
        func: F,
    ) -> VirtualMachineResult<()>
    where
        F: Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value>
            + 'static
            + Send
            + Sync,
    {
        Ok(self.state.try_insert_function(Function::foreign(
            ForeignFunction::mpc_online_builtin(builtin, Arc::new(func)),
        ))?)
    }

    pub(crate) fn try_register_mpc_online_foreign_method<F>(
        &mut self,
        receiver_type: &str,
        method_name: &str,
        builtin: MpcOnlineBuiltin,
        func: F,
    ) -> VirtualMachineResult<()>
    where
        F: Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value>
            + 'static
            + Send
            + Sync,
    {
        Ok(self.state.try_insert_method(
            receiver_type,
            method_name,
            Function::foreign(ForeignFunction::mpc_online_builtin(builtin, Arc::new(func))),
        )?)
    }

    #[track_caller]
    pub fn register_foreign_function<F>(&mut self, name: &str, func: F)
    where
        F: Fn(ForeignFunctionContext) -> Result<Value, String> + 'static + Send + Sync,
    {
        self.try_register_foreign_function(name, func)
            .expect("invalid foreign function registration");
    }

    #[track_caller]
    pub fn register_typed_foreign_method<F>(
        &mut self,
        receiver_type: &str,
        method_name: &str,
        canonical_name: &str,
        func: F,
    ) where
        F: Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value>
            + 'static
            + Send
            + Sync,
    {
        self.try_register_typed_foreign_method(receiver_type, method_name, canonical_name, func)
            .expect("invalid foreign method registration");
    }

    #[track_caller]
    pub fn register_typed_foreign_function<F>(&mut self, name: &str, func: F)
    where
        F: Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value>
            + 'static
            + Send
            + Sync,
    {
        self.try_register_typed_foreign_function(name, func)
            .expect("invalid foreign function registration");
    }

    /// Register a foreign object and return its typed VM handle.
    pub fn try_register_foreign_object<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> VirtualMachineResult<ForeignObjectRef> {
        Ok(self.state.try_register_foreign_object_ref(object)?)
    }

    /// Register a foreign object and return its typed VM handle.
    pub fn try_register_foreign_object_ref<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> VirtualMachineResult<ForeignObjectRef> {
        self.try_register_foreign_object(object)
    }

    /// Register a foreign object and return it as a VM value.
    pub fn try_register_foreign_object_value<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> VirtualMachineResult<Value> {
        Ok(Value::from(self.try_register_foreign_object(object)?))
    }

    #[track_caller]
    pub fn register_foreign_object<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> ForeignObjectRef {
        self.try_register_foreign_object(object)
            .expect("foreign object registration failed")
    }

    #[track_caller]
    pub fn register_foreign_object_ref<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> ForeignObjectRef {
        self.register_foreign_object(object)
    }

    #[track_caller]
    pub fn register_foreign_object_value<T: 'static + Send + Sync>(&mut self, object: T) -> Value {
        self.try_register_foreign_object_value(object)
            .expect("foreign object registration failed")
    }

    /// Get a foreign object by typed reference.
    pub fn get_foreign_object<T: 'static + Send + Sync>(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<Mutex<T>>> {
        self.state.get_foreign_object_ref(object_ref)
    }

    /// Get a foreign object by typed reference.
    pub fn get_foreign_object_ref<T: 'static + Send + Sync>(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<Mutex<T>>> {
        self.get_foreign_object(object_ref)
    }
}
