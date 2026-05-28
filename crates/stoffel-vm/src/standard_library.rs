use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{
    ForeignFunctionCallbackResult, ForeignFunctionContext, MpcOnlineBuiltin,
};
use crate::net::client_store::{ClientInputIndex, ClientOutputShareCount, ClientShareIndex};
use crate::runtime_hooks::HookEvent;
use crate::value_conversions::{usize_to_vm_i64, value_to_usize};
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{ShareData, ShareType, TableRef, Value};

const OUTPUT_SHARE_LIST_MAGIC: &[u8; 5] = b"VMOS1";

pub(crate) const FUNCTION_NAMES: &[&str] = &[
    "create_object",
    "create_array",
    "get_field",
    "set_field",
    "array_length",
    "array_push",
    "ClientStore.get_number_clients",
    "ClientStore.take_share",
    "ClientStore.take_share_fixed",
    "LocalStorage.store",
    "LocalStorage.load",
    "LocalStorage.retrieve",
    "LocalStorage.delete",
    "LocalStorage.exists",
    "MpcOutput.send_to_client",
    "create_closure",
    "call_closure",
    "get_upvalue",
    "set_upvalue",
    "print",
    "type",
];

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    macro_rules! register_standard_builtin {
        ($name:expr, $func:expr) => {
            vm.try_register_typed_foreign_function($name, $func)?;
        };
    }

    register_standard_builtin!("create_object", |mut ctx| ctx.create_object());

    register_standard_builtin!("create_array", |mut ctx| {
        let capacity = ctx
            .arg(0)
            .map(|value| value_to_usize(value, "array capacity"))
            .transpose()?
            .unwrap_or(0);

        ctx.create_array(capacity)
    });

    register_standard_builtin!("get_field", |mut ctx| {
        let (table_ref, key) = {
            let args = ctx.named_args("get_field");
            args.require_min(2, "at least 2 arguments: object and key")?;
            let target = args.cloned(0)?;
            let Some(table_ref) = TableRef::from_value(&target) else {
                return Ok(Value::Unit);
            };
            (table_ref, args.cloned(1)?)
        };

        let value = ctx
            .read_table_field(table_ref, &key)?
            .unwrap_or(Value::Unit);

        if ctx.hooks_enabled() {
            match table_ref {
                TableRef::Object(object_ref) => {
                    let event = HookEvent::ObjectFieldRead(object_ref, key, value.clone());
                    ctx.trigger_hook_with_snapshot(&event)?;
                }
                TableRef::Array(array_ref) => {
                    let event = HookEvent::ArrayElementRead(array_ref, key, value.clone());
                    ctx.trigger_hook_with_snapshot(&event)?;
                }
            }
        }

        Ok(value)
    });

    register_standard_builtin!("set_field", |mut ctx| {
        let (table_ref, key, new_value) = {
            let args = ctx.named_args("set_field");
            args.require_min(3, "3 arguments: object, key, and value")?;
            (
                args.table_ref(0, "First argument")?,
                args.cloned(1)?,
                args.cloned(2)?,
            )
        };

        let hooks_enabled = ctx.hooks_enabled();
        if !hooks_enabled {
            ctx.set_table_field(table_ref, key, new_value)?;
            return Ok(Value::Unit);
        }

        let old_value = ctx
            .read_table_field(table_ref, &key)?
            .unwrap_or(Value::Unit);
        ctx.set_table_field(table_ref, key.clone(), new_value.clone())?;
        match table_ref {
            TableRef::Object(object_ref) => {
                let event = HookEvent::ObjectFieldWrite(object_ref, key, old_value, new_value);
                ctx.trigger_hook_with_snapshot(&event)?;
            }
            TableRef::Array(array_ref) => {
                let event = HookEvent::ArrayElementWrite(array_ref, key, old_value, new_value);
                ctx.trigger_hook_with_snapshot(&event)?;
            }
        }

        Ok(Value::Unit)
    });

    register_standard_builtin!("array_length", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("array_length");
            args.require_exact(1, "1 argument: array")?;
            args.array_ref(0, "First argument")?
        };

        let len = ctx.read_array_ref_len(array_ref)?;
        let len = usize_to_vm_i64(len, "array length")?;
        Ok(Value::I64(len))
    });

    register_standard_builtin!("array_push", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("array_push");
            args.require_min(2, "at least 2 arguments: array and value")?;
            args.array_ref(0, "First argument")?
        };

        let len = ctx.push_array_args_from(array_ref, 1, "array_push")?;
        Ok(Value::I64(usize_to_vm_i64(len, "array length")?))
    });

    register_standard_builtin!("ClientStore.get_number_clients", |ctx| {
        let count = ctx.client_store_len();
        Ok(Value::I64(usize_to_vm_i64(count, "client count")?))
    });

    register_standard_builtin!("ClientStore.take_share", |ctx| {
        let args = ctx.named_args("ClientStore.take_share");
        args.require_exact(2, "2 arguments: client_index, share_index")?;

        let client_index = ClientInputIndex::new(args.usize(0, "client_index")?);
        let share_index = ClientShareIndex::new(args.usize(1, "share_index")?);

        let client_id = ctx
            .client_id_at_index(client_index)
            .ok_or_else(|| format!("No client at index {}", client_index))?;

        Ok(ctx.load_client_share(client_id, share_index)?)
    });

    register_standard_builtin!("ClientStore.take_share_fixed", |ctx| {
        let args = ctx.named_args("ClientStore.take_share_fixed");
        args.require_exact(2, "2 arguments: client_index, share_index")?;

        let client_index = ClientInputIndex::new(args.usize(0, "client_index")?);
        let share_index = ClientShareIndex::new(args.usize(1, "share_index")?);

        let client_id = ctx
            .client_id_at_index(client_index)
            .ok_or_else(|| format!("No client at index {}", client_index))?;

        Ok(ctx.load_client_share_as(
            client_id,
            share_index,
            ShareType::default_secret_fixed_point(),
        )?)
    });

    register_standard_builtin!("LocalStorage.store", |mut ctx| {
        let (key_value, stored_value) = {
            let args = ctx.named_args("LocalStorage.store");
            args.require_exact(2, "2 arguments: key and value")?;
            (args.cloned(0)?, args.cloned(1)?)
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        ctx.local_storage_store_value(&key, &stored_value)?;
        Ok(Value::Bool(true))
    });

    register_standard_builtin!("LocalStorage.load", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.load");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(ctx.local_storage_load_value(&key)?.unwrap_or(Value::Unit))
    });

    register_standard_builtin!("LocalStorage.retrieve", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.retrieve");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(ctx.local_storage_load_value(&key)?.unwrap_or(Value::Unit))
    });

    register_standard_builtin!("LocalStorage.delete", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.delete");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(Value::Bool(ctx.local_storage_delete(&key)?))
    });

    register_standard_builtin!("LocalStorage.exists", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.exists");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(Value::Bool(ctx.local_storage_exists(&key)?))
    });

    vm.try_register_mpc_online_foreign_function(
        MpcOnlineBuiltin::OutputSendToClient,
        |mut ctx| {
            let (client_id, output_value) = {
                let args = ctx.named_args("MpcOutput.send_to_client");
                args.require_exact(2, "2 arguments: client_id, share_value")?;
                (args.usize(0, "client_id")?, args.cloned(1)?)
            };

            let (share_bytes, share_count) = match &output_value {
                Value::Array(_) => {
                    let Some((_share_type, share_data)) = ctx.extract_homogeneous_share_array(
                        &output_value,
                        "MpcOutput.send_to_client share_value",
                    )?
                    else {
                        return Err(
                            "MpcOutput.send_to_client requires at least one output share".into(),
                        );
                    };
                    let share_count = ClientOutputShareCount::try_new(share_data.len())
                        .map_err(|error| error.to_string())?;
                    (encode_output_share_list(&share_data)?, share_count)
                }
                _ => {
                    let (_share_type, share_data) = ctx.extract_share_data(&output_value)?;
                    (
                        share_data.as_bytes().to_vec(),
                        ClientOutputShareCount::one(),
                    )
                }
            };

            ctx.send_output_to_client(client_id, &share_bytes, share_count)?;

            Ok(Value::Bool(true))
        },
    )?;

    register_standard_builtin!("create_closure", |mut ctx| {
        let (function_name, upvalue_names) = {
            let args = ctx.named_args("create_closure");
            args.require_min(1, "at least 1 argument: function_name")?;
            let function_name = args.cloned_string(0, "First argument")?;

            let mut upvalue_names = Vec::new();
            for arg in args.tail_from(1)? {
                match arg {
                    Value::String(name) => upvalue_names.push(name.clone()),
                    _ => return Err("Upvalue names must be strings".into()),
                }
            }

            (function_name, upvalue_names)
        };

        Ok(ctx.create_closure_value(function_name, &upvalue_names)?)
    });

    register_standard_builtin!("call_closure", |mut ctx| {
        let (closure_value, closure_args) = {
            let args = ctx.named_args("call_closure");
            args.require_min(1, "at least 1 argument: closure")?;
            (args.cloned(0)?, args.tail_from(1)?.to_vec())
        };

        ctx.call_closure_value(&closure_value, &closure_args)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("get_upvalue", |ctx| {
        let args = ctx.named_args("get_upvalue");
        args.require_exact(1, "1 argument: name")?;
        let name = args.string(0, "Upvalue name")?;

        Ok(ctx.get_upvalue_value(name)?)
    });

    register_standard_builtin!("set_upvalue", |mut ctx| {
        let (name, new_value) = {
            let args = ctx.named_args("set_upvalue");
            args.require_min(2, "2 arguments: name and value")?;
            (args.cloned_string(0, "Upvalue name")?, args.cloned(1)?)
        };

        ctx.set_upvalue_value(&name, new_value)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("print", |ctx| {
        let args = ctx.args();
        let mut output = String::new();
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                output.push(' ');
            }
            match arg {
                Value::String(s) => output.push_str(s),
                _ => output.push_str(&format!("{:?}", arg)),
            }
        }
        ctx.write_output_line(&output)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("type", |ctx| {
        let args = ctx.named_args("type");
        args.require_exact(1, "1 argument")?;

        Ok(Value::String(args.get(0)?.type_name().to_string()))
    });

    Ok(())
}

pub(crate) fn encode_output_share_list(shares: &[ShareData]) -> Result<Vec<u8>, String> {
    if shares.len() > u32::MAX as usize {
        return Err("Too many output shares to send to client".to_owned());
    }

    let payload_len = shares.iter().try_fold(
        OUTPUT_SHARE_LIST_MAGIC.len() + std::mem::size_of::<u32>(),
        |acc, share| {
            let len = share.as_bytes().len();
            if len > u32::MAX as usize {
                return Err("Output share is too large to send to client".to_owned());
            }
            acc.checked_add(std::mem::size_of::<u32>())
                .and_then(|value| value.checked_add(len))
                .ok_or_else(|| "Output share payload is too large".to_owned())
        },
    )?;

    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(OUTPUT_SHARE_LIST_MAGIC);
    payload.extend_from_slice(&(shares.len() as u32).to_le_bytes());
    for share in shares {
        let bytes = share.as_bytes();
        payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    Ok(payload)
}

fn local_storage_key(
    ctx: &mut ForeignFunctionContext<'_>,
    key_value: Value,
) -> ForeignFunctionCallbackResult<Vec<u8>> {
    match key_value {
        Value::String(key) => Ok(key.into_bytes()),
        key_value => ctx.read_byte_array(&key_value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::curve::{MpcCurveConfig, MpcFieldKind};
    use crate::net::mpc_engine::{
        MpcCapabilities, MpcEngine, MpcEngineClientOutput, MpcEngineError, MpcEngineResult,
        MpcSessionTopology,
    };
    use crate::output::{VmOutputResult, VmOutputSink};
    use crate::storage::RedbLocalStorage;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData};
    use stoffelnet::network_utils::ClientId;

    #[derive(Clone, Default)]
    struct RecordingOutputSink {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl VmOutputSink for RecordingOutputSink {
        fn write_line(&self, line: &str) -> VmOutputResult<()> {
            self.lines.lock().push(line.to_owned());
            Ok(())
        }
    }

    struct StorageTestEngine {
        instance_id: u64,
    }

    impl StorageTestEngine {
        const fn new(instance_id: u64) -> Self {
            Self { instance_id }
        }
    }

    impl MpcEngine for StorageTestEngine {
        fn protocol_name(&self) -> &'static str {
            "avss-mpc"
        }

        fn topology(&self) -> MpcSessionTopology {
            MpcSessionTopology::try_new(self.instance_id, 0, 5, 1).expect("valid topology")
        }

        fn is_ready(&self) -> bool {
            true
        }

        fn start(&self) -> MpcEngineResult<()> {
            Ok(())
        }

        fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
            Err(MpcEngineError::operation_failed(
                "storage_test",
                "input_share is not used",
            ))
        }

        fn open_share(
            &self,
            _ty: ShareType,
            _share_bytes: &[u8],
        ) -> MpcEngineResult<ClearShareValue> {
            Err(MpcEngineError::operation_failed(
                "storage_test",
                "open_share is not used",
            ))
        }

        fn curve_config(&self) -> MpcCurveConfig {
            MpcCurveConfig::Bls12_381
        }

        fn field_kind(&self) -> MpcFieldKind {
            MpcFieldKind::Bls12_381Fr
        }
    }

    #[derive(Clone, Default)]
    struct OutputRecordingEngine {
        sent: Arc<Mutex<Vec<(ClientId, Vec<u8>, ClientOutputShareCount)>>>,
    }

    impl MpcEngine for OutputRecordingEngine {
        fn protocol_name(&self) -> &'static str {
            "avss-mpc"
        }

        fn topology(&self) -> MpcSessionTopology {
            MpcSessionTopology::try_new(7, 0, 5, 1).expect("valid topology")
        }

        fn is_ready(&self) -> bool {
            true
        }

        fn start(&self) -> MpcEngineResult<()> {
            Ok(())
        }

        fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
            Err(MpcEngineError::operation_failed(
                "output_recording",
                "input_share is not used",
            ))
        }

        fn open_share(
            &self,
            _ty: ShareType,
            _share_bytes: &[u8],
        ) -> MpcEngineResult<ClearShareValue> {
            Err(MpcEngineError::operation_failed(
                "output_recording",
                "open_share is not used",
            ))
        }

        fn curve_config(&self) -> MpcCurveConfig {
            MpcCurveConfig::Bls12_381
        }

        fn field_kind(&self) -> MpcFieldKind {
            MpcFieldKind::Bls12_381Fr
        }

        fn capabilities(&self) -> MpcCapabilities {
            MpcCapabilities::CLIENT_OUTPUT
        }

        fn as_client_output(&self) -> Option<&dyn MpcEngineClientOutput> {
            Some(self)
        }
    }

    impl MpcEngineClientOutput for OutputRecordingEngine {
        fn send_output_to_client(
            &self,
            client_id: ClientId,
            shares: &[u8],
            output_share_count: ClientOutputShareCount,
        ) -> MpcEngineResult<()> {
            self.sent
                .lock()
                .push((client_id, shares.to_vec(), output_share_count));
            Ok(())
        }
    }

    #[test]
    fn print_uses_configured_vm_output_sink() {
        let output_sink = RecordingOutputSink::default();
        let lines = Arc::clone(&output_sink.lines);
        let mut vm = VirtualMachine::builder()
            .with_output_sink(output_sink)
            .try_build()
            .expect("build VM");

        vm.execute_with_args(
            "print",
            &[Value::String("answer".to_owned()), Value::I64(42)],
        )
        .expect("print should write through output sink");

        assert_eq!(lines.lock().as_slice(), &["answer 42"]);
    }

    #[test]
    fn cloned_vm_preserves_configured_output_sink() {
        let output_sink = RecordingOutputSink::default();
        let lines = Arc::clone(&output_sink.lines);
        let vm = VirtualMachine::builder()
            .with_output_sink(output_sink)
            .try_build()
            .expect("build VM");
        let mut cloned = vm
            .try_clone_with_independent_state()
            .expect("clone VM with configured output sink");

        cloned
            .execute_with_args("print", &[Value::String("clone".to_owned())])
            .expect("print should use cloned VM output sink");

        assert_eq!(lines.lock().as_slice(), &["clone"]);
    }

    #[test]
    fn local_storage_builtins_persist_vm_values() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let stored = Value::Share(
            ShareType::secret_int(64),
            ShareData::Feldman {
                data: vec![1, 2, 3],
                commitments: vec![vec![4, 5], vec![6]],
            },
        );

        {
            let storage = RedbLocalStorage::new(&path).expect("open storage");
            let mut vm = VirtualMachine::builder()
                .with_local_storage(storage)
                .with_mpc_engine(Arc::new(StorageTestEngine::new(7)))
                .try_build()
                .expect("build VM");

            assert_eq!(
                vm.execute_with_args(
                    "LocalStorage.store",
                    &[Value::String("share".to_owned()), stored.clone()]
                )
                .expect("store value"),
                Value::Bool(true)
            );
            assert_eq!(
                vm.execute_with_args("LocalStorage.exists", &[Value::String("share".to_owned())])
                    .expect("exists"),
                Value::Bool(true)
            );

            let mut cloned = vm
                .try_clone_with_independent_state()
                .expect("clone VM with storage");
            assert_eq!(
                cloned
                    .execute_with_args("LocalStorage.load", &[Value::String("share".to_owned())])
                    .expect("load from clone"),
                stored.clone()
            );
        }

        let storage = RedbLocalStorage::new(&path).expect("reopen storage");
        let mut vm = VirtualMachine::builder()
            .with_local_storage(storage)
            .with_mpc_engine(Arc::new(StorageTestEngine::new(99)))
            .try_build()
            .expect("build VM");

        assert_eq!(
            vm.execute_with_args("LocalStorage.load", &[Value::String("share".to_owned())])
                .expect("load value"),
            stored
        );
        assert_eq!(
            vm.execute_with_args("LocalStorage.delete", &[Value::String("share".to_owned())])
                .expect("delete value"),
            Value::Bool(true)
        );
        assert_eq!(
            vm.execute_with_args(
                "LocalStorage.retrieve",
                &[Value::String("share".to_owned())]
            )
            .expect("load missing"),
            Value::Unit
        );
    }

    #[test]
    fn mpc_output_array_sends_bounded_share_list_envelope() {
        let engine = OutputRecordingEngine::default();
        let sent = Arc::clone(&engine.sent);
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(Arc::new(engine))
            .try_build()
            .expect("build VM");

        let output_array = vm
            .execute_with_args("create_array", &[Value::I64(2)])
            .expect("create output array");
        let first = Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![1, 2, 3]));
        let second = Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![4, 5]));

        vm.execute_with_args("array_push", &[output_array.clone(), first])
            .expect("push first output share");
        vm.execute_with_args("array_push", &[output_array.clone(), second])
            .expect("push second output share");

        assert_eq!(
            vm.execute_with_args("MpcOutput.send_to_client", &[Value::I64(7), output_array])
                .expect("send output shares"),
            Value::Bool(true)
        );

        let sent = sent.lock();
        assert_eq!(sent.len(), 1);
        let (client_id, payload, count) = &sent[0];
        assert_eq!(*client_id, 7);
        assert_eq!(count.count(), 2);

        let mut offset = OUTPUT_SHARE_LIST_MAGIC.len();
        assert_eq!(&payload[..offset], OUTPUT_SHARE_LIST_MAGIC);
        assert_eq!(read_test_u32(payload, &mut offset), 2);
        assert_eq!(read_test_vec(payload, &mut offset), vec![1, 2, 3]);
        assert_eq!(read_test_vec(payload, &mut offset), vec![4, 5]);
        assert_eq!(offset, payload.len());
    }

    fn read_test_u32(bytes: &[u8], offset: &mut usize) -> u32 {
        let end = *offset + std::mem::size_of::<u32>();
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&bytes[*offset..end]);
        *offset = end;
        u32::from_le_bytes(raw)
    }

    fn read_test_vec(bytes: &[u8], offset: &mut usize) -> Vec<u8> {
        let len = read_test_u32(bytes, offset) as usize;
        let end = *offset + len;
        let value = bytes[*offset..end].to_vec();
        *offset = end;
        value
    }
}
