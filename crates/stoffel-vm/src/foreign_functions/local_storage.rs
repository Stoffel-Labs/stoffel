use super::{ForeignFunctionCallbackResult, ForeignFunctionContext};
use stoffel_vm_types::core_types::Value;

impl<'a> ForeignFunctionContext<'a> {
    /// Persist a VM value in the configured local storage backend.
    pub fn local_storage_store_value(
        &mut self,
        key: &[u8],
        value: &Value,
    ) -> ForeignFunctionCallbackResult<()> {
        Ok(self.services.local_storage_store_value(key, value)?)
    }

    /// Load a VM value from the configured local storage backend.
    pub fn local_storage_load_value(
        &mut self,
        key: &[u8],
    ) -> ForeignFunctionCallbackResult<Option<Value>> {
        Ok(self.services.local_storage_load_value(key)?)
    }

    /// Delete a value from the configured local storage backend.
    pub fn local_storage_delete(&mut self, key: &[u8]) -> ForeignFunctionCallbackResult<bool> {
        Ok(self.services.local_storage_delete(key)?)
    }

    /// Check whether a value exists in the configured local storage backend.
    pub fn local_storage_exists(&mut self, key: &[u8]) -> ForeignFunctionCallbackResult<bool> {
        Ok(self.services.local_storage_exists(key)?)
    }
}
