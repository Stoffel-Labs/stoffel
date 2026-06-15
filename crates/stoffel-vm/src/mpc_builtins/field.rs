//! Public (cleartext) field-arithmetic builtins for StoffelVM.
//!
//! These operate on *already-public* field elements — typically the result of
//! [`Share.open_field`](super::share) — encoded as canonically-serialized byte
//! arrays in the active MPC computation field. Every operation is local,
//! non-interactive and deterministic, so all parties compute identical results;
//! they carry no secrecy and never touch the network.
//!
//! The field is taken from the running MPC engine's curve configuration
//! (`Mpc.curve()`), so StoffelLang code never has to thread a curve name around.
//! This surface is what lets protocols such as joint random-bit sharing be
//! written directly in StoffelLang: reveal `r^2` with `open_field`, then use
//! `Field.sqrt` / `Field.inverse` on the public value and fold the result back
//! into the share with `Share.mul_field` / `Share.add_field`.

use crate::core_vm::VirtualMachine;
use crate::net::curve::MpcCurveConfig;
use crate::value_conversions::value_to_i64;
use crate::VirtualMachineResult;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffel_vm_types::core_types::Value;

/// Run `$body` with `$f` bound to the ark field type of the active curve.
macro_rules! dispatch_field {
    ($curve:expr, |$f:ident| $body:expr) => {{
        match $curve {
            MpcCurveConfig::Bls12_381 => {
                type $f = ark_bls12_381::Fr;
                $body
            }
            MpcCurveConfig::Bn254 => {
                type $f = ark_bn254::Fr;
                $body
            }
            MpcCurveConfig::Curve25519 | MpcCurveConfig::Ed25519 => {
                type $f = ark_curve25519::Fr;
                $body
            }
            MpcCurveConfig::Secp256k1 => {
                type $f = ark_secp256k1::Fr;
                $body
            }
            MpcCurveConfig::Secp256r1 => {
                type $f = ark_secp256r1::Fr;
                $body
            }
        }
    }};
}

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Field.from_int", |mut ctx| {
        let value = {
            let args = ctx.named_args("Field.from_int");
            args.require_exact(1, "1 argument: value (int)")?;
            args.cloned(0)?
        };
        let n = value_to_i64(&value, "value")?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| from_int_impl::<F>(n))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.zero", |mut ctx| {
        {
            let args = ctx.named_args("Field.zero");
            args.require_exact(0, "no arguments")?;
        }
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| serialize::<F>(F::ZERO))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.one", |mut ctx| {
        {
            let args = ctx.named_args("Field.one");
            args.require_exact(0, "no arguments")?;
        }
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| serialize::<F>(F::ONE))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.is_zero", |mut ctx| {
        let bytes = read_one("Field.is_zero", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let is_zero = dispatch_field!(curve, |F| Ok::<_, String>(deserialize::<F>(&bytes)?
            == F::ZERO))?;
        Ok(Value::Bool(is_zero))
    })?;

    vm.try_register_typed_foreign_function("Field.eq", |mut ctx| {
        let (a, b) = read_two("Field.eq", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let eq = dispatch_field!(curve, |F| Ok::<_, String>(deserialize::<F>(&a)?
            == deserialize::<F>(&b)?))?;
        Ok(Value::Bool(eq))
    })?;

    vm.try_register_typed_foreign_function("Field.add", |mut ctx| {
        let (a, b) = read_two("Field.add", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| serialize::<F>(deserialize::<F>(&a)?
            + deserialize::<F>(&b)?))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.sub", |mut ctx| {
        let (a, b) = read_two("Field.sub", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| serialize::<F>(deserialize::<F>(&a)?
            - deserialize::<F>(&b)?))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.mul", |mut ctx| {
        let (a, b) = read_two("Field.mul", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| serialize::<F>(deserialize::<F>(&a)?
            * deserialize::<F>(&b)?))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.neg", |mut ctx| {
        let bytes = read_one("Field.neg", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| serialize::<F>(-deserialize::<F>(&bytes)?))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.inverse", |mut ctx| {
        let bytes = read_one("Field.inverse", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| inverse_impl::<F>(&bytes))?;
        ctx.create_byte_array(&out)
    })?;

    vm.try_register_typed_foreign_function("Field.sqrt", |mut ctx| {
        let bytes = read_one("Field.sqrt", &mut ctx)?;
        let curve = ctx.require_mpc_runtime_info()?.curve_config();
        let out = dispatch_field!(curve, |F| sqrt_impl::<F>(&bytes))?;
        ctx.create_byte_array(&out)
    })?;

    Ok(())
}

fn read_one(
    name: &'static str,
    ctx: &mut crate::foreign_functions::ForeignFunctionContext<'_>,
) -> crate::foreign_functions::ForeignFunctionCallbackResult<Vec<u8>> {
    let value = {
        let args = ctx.named_args(name);
        args.require_exact(1, "1 argument: field_bytes")?;
        args.cloned(0)?
    };
    Ok(ctx.read_byte_array(&value)?)
}

fn read_two(
    name: &'static str,
    ctx: &mut crate::foreign_functions::ForeignFunctionContext<'_>,
) -> crate::foreign_functions::ForeignFunctionCallbackResult<(Vec<u8>, Vec<u8>)> {
    let (a_value, b_value) = {
        let args = ctx.named_args(name);
        args.require_exact(2, "2 arguments: a, b (field_bytes)")?;
        (args.cloned(0)?, args.cloned(1)?)
    };
    let a = ctx.read_byte_array(&a_value)?;
    let b = ctx.read_byte_array(&b_value)?;
    Ok((a, b))
}

fn deserialize<F: CanonicalDeserialize>(bytes: &[u8]) -> Result<F, String> {
    F::deserialize_compressed(bytes).map_err(|e| format!("deserialize field element: {e}"))
}

fn serialize<F: CanonicalSerialize>(value: F) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    value
        .serialize_compressed(&mut out)
        .map_err(|e| format!("serialize field element: {e}"))?;
    Ok(out)
}

fn from_int_impl<F: PrimeField>(n: i64) -> Result<Vec<u8>, String> {
    let magnitude = F::from(n.unsigned_abs());
    let value = if n < 0 { -magnitude } else { magnitude };
    serialize(value)
}

fn inverse_impl<F: PrimeField>(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = deserialize::<F>(bytes)?;
    let inverse = value
        .inverse()
        .ok_or_else(|| "field inverse is undefined for zero".to_string())?;
    serialize(inverse)
}

/// Canonical modular square root: the root in `[0, p/2]`, matching the
/// "0 < r' < p/2" convention. The choice is a deterministic function of the
/// (public) input, so every party agrees on the same root. Errors when the
/// input is not a quadratic residue.
fn sqrt_impl<F: PrimeField>(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = deserialize::<F>(bytes)?;
    let root = value
        .sqrt()
        .ok_or_else(|| "value is not a quadratic residue".to_string())?;
    let neg_root = -root;
    let canonical = if root.into_bigint() <= neg_root.into_bigint() {
        root
    } else {
        neg_root
    };
    serialize(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field, PrimeField};

    #[test]
    fn from_int_handles_sign() {
        let pos = deserialize::<Fr>(&from_int_impl::<Fr>(7).unwrap()).unwrap();
        let neg = deserialize::<Fr>(&from_int_impl::<Fr>(-7).unwrap()).unwrap();
        assert_eq!(pos, Fr::from(7u64));
        assert_eq!(neg, -Fr::from(7u64));
        assert_eq!(pos + neg, Fr::ZERO);
    }

    #[test]
    fn inverse_round_trips() {
        let value = Fr::from(7u64);
        let inv = deserialize::<Fr>(&inverse_impl::<Fr>(&serialize(value).unwrap()).unwrap())
            .unwrap();
        assert_eq!(value * inv, Fr::ONE);
    }

    #[test]
    fn inverse_of_zero_errors() {
        assert!(inverse_impl::<Fr>(&serialize(Fr::ZERO).unwrap()).is_err());
    }

    #[test]
    fn sqrt_is_canonical_and_correct() {
        // For every x, sqrt(x^2) must be a square root of x^2 and lie in the
        // lower half, so the result is deterministic regardless of sign of x.
        for raw in [1u64, 2, 3, 7, 12345] {
            let x = Fr::from(raw);
            let square = x * x;
            let root_pos =
                deserialize::<Fr>(&sqrt_impl::<Fr>(&serialize(square).unwrap()).unwrap()).unwrap();
            let root_neg =
                deserialize::<Fr>(&sqrt_impl::<Fr>(&serialize((-x) * (-x)).unwrap()).unwrap())
                    .unwrap();
            // Same canonical root for x and -x (their squares are equal).
            assert_eq!(root_pos, root_neg);
            assert_eq!(root_pos * root_pos, square);
            // Canonical: in the lower half [0, p/2].
            assert!(root_pos.into_bigint() <= (-root_pos).into_bigint());
        }
    }

    #[test]
    fn sqrt_of_non_residue_errors() {
        // Find a non-residue and confirm the builtin rejects it.
        let mut candidate = Fr::from(2u64);
        while candidate.legendre().is_qr() {
            candidate += Fr::ONE;
        }
        assert!(sqrt_impl::<Fr>(&serialize(candidate).unwrap()).is_err());
    }
}
