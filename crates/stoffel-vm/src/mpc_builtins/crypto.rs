use crate::core_vm::VirtualMachine;
use crate::VirtualMachineResult;
use sha2::{Digest, Sha256, Sha512};
use stoffel_vm_types::core_types::Value;

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    register_hash_builtins(vm)?;
    register_curve_builtins(vm)?;
    Ok(())
}

fn register_hash_builtins(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Crypto.sha256", |mut ctx| {
        let hash = {
            let data = {
                let args = ctx.named_args("Crypto.sha256");
                args.require_exact(1, "1 argument: data (byte array)")?;
                args.cloned(0)?
            };

            let bytes = ctx.read_byte_array(&data)?;
            Sha256::digest(&bytes)
        };

        ctx.create_byte_array(&hash)
    })?;

    vm.try_register_typed_foreign_function("Crypto.sha512", |mut ctx| {
        let hash = {
            let data = {
                let args = ctx.named_args("Crypto.sha512");
                args.require_exact(1, "1 argument: data (byte array)")?;
                args.cloned(0)?
            };

            let bytes = ctx.read_byte_array(&data)?;
            Sha512::digest(&bytes)
        };

        ctx.create_byte_array(&hash)
    })?;

    Ok(())
}

fn register_curve_builtins(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Crypto.hash_to_field", |mut ctx| {
        let (hash_bytes, curve_name) = {
            let (hash_value, curve_value) = {
                let args = ctx.named_args("Crypto.hash_to_field");
                args.require_min(2, "2 arguments: hash_bytes, curve_name")?;
                (args.cloned(0)?, args.cloned(1)?)
            };

            let hash_bytes = ctx.read_byte_array(&hash_value)?;

            let curve_name = match curve_value {
                Value::String(s) => s,
                _ => return Err("curve_name must be a string".into()),
            };

            (hash_bytes, curve_name)
        };

        use crate::net::curve::MpcCurveConfig;
        use ark_ff::PrimeField;

        let curve = curve_name
            .parse::<MpcCurveConfig>()
            .map_err(|e| format!("Invalid curve name: {}", e))?;

        let out_bytes = match curve {
            MpcCurveConfig::Bls12_381 => {
                let field_elem = ark_bls12_381::Fr::from_be_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
            MpcCurveConfig::Bn254 => {
                let field_elem = ark_bn254::Fr::from_be_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
            MpcCurveConfig::Curve25519 | MpcCurveConfig::Ed25519 => {
                let field_elem = ark_curve25519::Fr::from_le_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
            MpcCurveConfig::Secp256k1 => {
                let field_elem = ark_secp256k1::Fr::from_be_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
            MpcCurveConfig::Secp256r1 => {
                let field_elem = ark_secp256r1::Fr::from_be_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
        };

        ctx.create_byte_array(&out_bytes)
    })?;

    vm.try_register_typed_foreign_function("Crypto.field_inv", |mut ctx| {
        let (field_bytes, curve_name) = {
            let (field_value, curve_value) = {
                let args = ctx.named_args("Crypto.field_inv");
                args.require_exact(2, "2 arguments: field_bytes, curve_name")?;
                (args.cloned(0)?, args.cloned(1)?)
            };

            let field_bytes = ctx.read_byte_array(&field_value)?;
            let curve_name = match curve_value {
                Value::String(s) => s,
                _ => return Err("curve_name must be a string".into()),
            };

            (field_bytes, curve_name)
        };

        let out_bytes = field_inverse_for_curve(&field_bytes, &curve_name)?;
        ctx.create_byte_array(&out_bytes)
    })?;

    vm.try_register_typed_foreign_function("Crypto.point_x_to_field", |mut ctx| {
        let (point_bytes, curve_name) = {
            let (point_value, curve_value) = {
                let args = ctx.named_args("Crypto.point_x_to_field");
                args.require_exact(2, "2 arguments: point_bytes, curve_name")?;
                (args.cloned(0)?, args.cloned(1)?)
            };

            let point_bytes = ctx.read_byte_array(&point_value)?;
            let curve_name = match curve_value {
                Value::String(s) => s,
                _ => return Err("curve_name must be a string".into()),
            };

            (point_bytes, curve_name)
        };

        let out_bytes = point_x_to_field_for_curve(&point_bytes, &curve_name)?;
        ctx.create_byte_array(&out_bytes)
    })?;

    vm.try_register_typed_foreign_function("Crypto.field_to_scalar_bytes", |mut ctx| {
        let (field_bytes, curve_name) = {
            let (field_value, curve_value) = {
                let args = ctx.named_args("Crypto.field_to_scalar_bytes");
                args.require_exact(2, "2 arguments: field_bytes, curve_name")?;
                (args.cloned(0)?, args.cloned(1)?)
            };

            let field_bytes = ctx.read_byte_array(&field_value)?;
            let curve_name = match curve_value {
                Value::String(s) => s,
                _ => return Err("curve_name must be a string".into()),
            };

            (field_bytes, curve_name)
        };

        let out_bytes = field_to_scalar_bytes_for_curve(&field_bytes, &curve_name)?;
        ctx.create_byte_array(&out_bytes)
    })?;

    vm.try_register_typed_foreign_function("Crypto.point_to_sec1", |mut ctx| {
        let (point_bytes, curve_name) = {
            let (point_value, curve_value) = {
                let args = ctx.named_args("Crypto.point_to_sec1");
                args.require_exact(2, "2 arguments: point_bytes, curve_name")?;
                (args.cloned(0)?, args.cloned(1)?)
            };

            let point_bytes = ctx.read_byte_array(&point_value)?;
            let curve_name = match curve_value {
                Value::String(s) => s,
                _ => return Err("curve_name must be a string".into()),
            };

            (point_bytes, curve_name)
        };

        let out_bytes = point_to_sec1_for_curve(&point_bytes, &curve_name)?;
        ctx.create_byte_array(&out_bytes)
    })?;

    vm.try_register_typed_foreign_function("Crypto.hash_to_g1", |mut ctx| {
        let out = {
            let data = {
                let args = ctx.named_args("Crypto.hash_to_g1");
                args.require_exact(1, "1 argument: data (byte array)")?;
                args.cloned(0)?
            };

            let bytes = ctx.read_byte_array(&data)?;
            let point = hash_to_bls12381_g1(&bytes)?;

            use ark_serialize::CanonicalSerialize;
            let mut out = Vec::new();
            point
                .serialize_compressed(&mut out)
                .map_err(|e| format!("serialize G1 point: {}", e))?;
            out
        };

        ctx.create_byte_array(&out)
    })?;

    Ok(())
}

fn field_inverse_for_curve(field_bytes: &[u8], curve_name: &str) -> Result<Vec<u8>, String> {
    use crate::net::curve::MpcCurveConfig;

    let curve = curve_name
        .parse::<MpcCurveConfig>()
        .map_err(|e| format!("Invalid curve name: {}", e))?;

    match curve {
        MpcCurveConfig::Bls12_381 => invert_field_element::<ark_bls12_381::Fr>(field_bytes),
        MpcCurveConfig::Bn254 => invert_field_element::<ark_bn254::Fr>(field_bytes),
        MpcCurveConfig::Curve25519 | MpcCurveConfig::Ed25519 => {
            invert_field_element::<ark_curve25519::Fr>(field_bytes)
        }
        MpcCurveConfig::Secp256k1 => invert_field_element::<ark_secp256k1::Fr>(field_bytes),
        MpcCurveConfig::Secp256r1 => invert_field_element::<ark_secp256r1::Fr>(field_bytes),
    }
}

fn invert_field_element<F>(field_bytes: &[u8]) -> Result<Vec<u8>, String>
where
    F: ark_ff::Field + ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize,
{
    let value = F::deserialize_compressed(field_bytes)
        .map_err(|e| format!("deserialize field element: {}", e))?;
    let inverse = value
        .inverse()
        .ok_or_else(|| "field inverse is undefined for zero".to_string())?;
    serialize_field_element(inverse)
}

fn point_x_to_field_for_curve(point_bytes: &[u8], curve_name: &str) -> Result<Vec<u8>, String> {
    use crate::net::curve::MpcCurveConfig;

    let curve = curve_name
        .parse::<MpcCurveConfig>()
        .map_err(|e| format!("Invalid curve name: {}", e))?;

    match curve {
        MpcCurveConfig::Secp256k1 => {
            point_x_to_field::<ark_secp256k1::Affine, ark_secp256k1::Fr>(point_bytes)
        }
        MpcCurveConfig::Secp256r1 => {
            point_x_to_field::<ark_secp256r1::Affine, ark_secp256r1::Fr>(point_bytes)
        }
        other => Err(format!(
            "Crypto.point_x_to_field supports secp256k1 and p-256, got {}",
            other.name()
        )),
    }
}

fn field_to_scalar_bytes_for_curve(
    field_bytes: &[u8],
    curve_name: &str,
) -> Result<Vec<u8>, String> {
    use crate::net::curve::MpcCurveConfig;

    let curve = curve_name
        .parse::<MpcCurveConfig>()
        .map_err(|e| format!("Invalid curve name: {}", e))?;

    match curve {
        MpcCurveConfig::Secp256k1 => field_to_fixed_be_bytes::<ark_secp256k1::Fr>(field_bytes, 32),
        MpcCurveConfig::Secp256r1 => field_to_fixed_be_bytes::<ark_secp256r1::Fr>(field_bytes, 32),
        other => Err(format!(
            "Crypto.field_to_scalar_bytes supports secp256k1 and p-256, got {}",
            other.name()
        )),
    }
}

fn point_to_sec1_for_curve(point_bytes: &[u8], curve_name: &str) -> Result<Vec<u8>, String> {
    use crate::net::curve::MpcCurveConfig;

    let curve = curve_name
        .parse::<MpcCurveConfig>()
        .map_err(|e| format!("Invalid curve name: {}", e))?;

    match curve {
        MpcCurveConfig::Secp256k1 => point_to_sec1::<ark_secp256k1::Affine>(point_bytes),
        MpcCurveConfig::Secp256r1 => point_to_sec1::<ark_secp256r1::Affine>(point_bytes),
        other => Err(format!(
            "Crypto.point_to_sec1 supports secp256k1 and p-256, got {}",
            other.name()
        )),
    }
}

fn point_x_to_field<A, Scalar>(point_bytes: &[u8]) -> Result<Vec<u8>, String>
where
    A: ark_ec::AffineRepr + ark_serialize::CanonicalDeserialize,
    A::BaseField: ark_ff::PrimeField,
    Scalar: ark_ff::PrimeField + ark_serialize::CanonicalSerialize,
{
    use ark_ff::{BigInteger, PrimeField};

    let point =
        A::deserialize_compressed(point_bytes).map_err(|e| format!("deserialize point: {}", e))?;
    let (x, _) = point
        .xy()
        .ok_or_else(|| "point is the point at infinity".to_string())?;
    let r = Scalar::from_be_bytes_mod_order(&x.into_bigint().to_bytes_be());
    serialize_field_element(r)
}

fn field_to_fixed_be_bytes<F>(field_bytes: &[u8], width: usize) -> Result<Vec<u8>, String>
where
    F: ark_ff::PrimeField + ark_serialize::CanonicalDeserialize,
{
    use ark_ff::BigInteger;

    let value = F::deserialize_compressed(field_bytes)
        .map_err(|e| format!("deserialize field element: {}", e))?;
    fixed_be_bytes(&value.into_bigint().to_bytes_be(), width, "field element")
}

fn point_to_sec1<A>(point_bytes: &[u8]) -> Result<Vec<u8>, String>
where
    A: ark_ec::AffineRepr + ark_serialize::CanonicalDeserialize,
    A::BaseField: ark_ff::PrimeField,
{
    use ark_ff::{BigInteger, PrimeField};

    let point =
        A::deserialize_compressed(point_bytes).map_err(|e| format!("deserialize point: {}", e))?;
    let (x, y) = point
        .xy()
        .ok_or_else(|| "point is the point at infinity".to_string())?;
    let x_bytes = fixed_be_bytes(&x.into_bigint().to_bytes_be(), 32, "point x-coordinate")?;
    let mut out = Vec::with_capacity(33);
    out.push(if y.into_bigint().is_odd() { 0x03 } else { 0x02 });
    out.extend_from_slice(&x_bytes);
    Ok(out)
}

fn fixed_be_bytes(bytes: &[u8], width: usize, label: &str) -> Result<Vec<u8>, String> {
    if bytes.len() > width {
        return Err(format!("{label} does not fit in {width} bytes"));
    }
    let mut out = vec![0u8; width];
    out[width - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn serialize_field_element<F>(field_elem: F) -> Result<Vec<u8>, String>
where
    F: ark_serialize::CanonicalSerialize,
{
    let mut out = Vec::new();
    field_elem
        .serialize_compressed(&mut out)
        .map_err(|e| format!("serialize field element: {}", e))?;
    Ok(out)
}

fn hash_to_bls12381_g1(bytes: &[u8]) -> Result<ark_bls12_381::G1Affine, String> {
    use ark_bls12_381::{Fq, G1Affine};
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    for counter in 0u32..256 {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();
        let x = Fq::from_be_bytes_mod_order(&hash);

        if let Some(point) = G1Affine::get_point_from_x_unchecked(x, false) {
            if point.is_on_curve() && !point.is_zero() {
                let cleared = point.clear_cofactor();
                if !cleared.is_zero() {
                    return Ok(cleared);
                }
            }
        }
    }

    Err("hash_to_g1: failed to find valid point after 256 attempts".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        field_inverse_for_curve, field_to_scalar_bytes_for_curve, point_to_sec1_for_curve,
        point_x_to_field_for_curve, serialize_field_element,
    };
    use ark_ec::{AffineRepr, PrimeGroup};
    use ark_ff::{BigInteger, Field, One, PrimeField};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    #[test]
    fn field_inverse_round_trips_for_ecdsa_curves() {
        assert_field_inverse::<ark_secp256k1::Fr>("secp256k1");
        assert_field_inverse::<ark_secp256r1::Fr>("p-256");
    }

    #[test]
    fn point_x_to_field_extracts_generator_x_coordinate() {
        assert_point_x_to_field::<ark_secp256k1::Projective, ark_secp256k1::Fr>("secp256k1");
        assert_point_x_to_field::<ark_secp256r1::Projective, ark_secp256r1::Fr>("p-256");
    }

    #[test]
    fn ecdsa_output_conversions_are_standard_width() {
        assert_field_to_scalar_bytes::<ark_secp256k1::Fr>("secp256k1");
        assert_field_to_scalar_bytes::<ark_secp256r1::Fr>("p-256");
        assert_point_to_sec1::<ark_secp256k1::Projective>("secp256k1");
        assert_point_to_sec1::<ark_secp256r1::Projective>("p-256");
    }

    fn assert_field_inverse<F>(curve_name: &str)
    where
        F: Field
            + One
            + From<u64>
            + PartialEq
            + ark_serialize::CanonicalDeserialize
            + ark_serialize::CanonicalSerialize,
    {
        let value = F::from(7u64);
        let value_bytes = serialize_field_element(value).expect("serialize field value");
        let inverse_bytes =
            field_inverse_for_curve(&value_bytes, curve_name).expect("invert field element");
        let inverse =
            F::deserialize_compressed(inverse_bytes.as_slice()).expect("deserialize field inverse");
        assert_eq!(value * inverse, F::one());
    }

    fn assert_point_x_to_field<G, Scalar>(curve_name: &str)
    where
        G: ark_ec::CurveGroup + PrimeGroup,
        G::Affine: CanonicalSerialize + AffineRepr,
        G::BaseField: PrimeField,
        <G::Affine as AffineRepr>::BaseField: ark_ff::PrimeField,
        Scalar: ark_ff::PrimeField + CanonicalDeserialize + CanonicalSerialize,
    {
        let generator = G::generator().into_affine();
        let mut point_bytes = Vec::new();
        generator
            .serialize_compressed(&mut point_bytes)
            .expect("serialize generator");
        let r_bytes =
            point_x_to_field_for_curve(&point_bytes, curve_name).expect("extract x-coordinate");
        let r = Scalar::deserialize_compressed(r_bytes.as_slice()).expect("deserialize r");
        let (x, _) = generator.xy().expect("generator must not be infinity");
        let expected = Scalar::from_be_bytes_mod_order(&x.into_bigint().to_bytes_be());
        assert_eq!(r, expected);
    }

    fn assert_field_to_scalar_bytes<F>(curve_name: &str)
    where
        F: PrimeField + From<u64> + CanonicalDeserialize + CanonicalSerialize,
    {
        let value = F::from(7u64);
        let value_bytes = serialize_field_element(value).expect("serialize field value");
        let standard_bytes =
            field_to_scalar_bytes_for_curve(&value_bytes, curve_name).expect("convert scalar");
        assert_eq!(standard_bytes.len(), 32);
        assert_eq!(standard_bytes[31], 7);
    }

    fn assert_point_to_sec1<G>(curve_name: &str)
    where
        G: ark_ec::CurveGroup + PrimeGroup,
        G::Affine: CanonicalSerialize + AffineRepr,
        G::BaseField: PrimeField,
    {
        let generator = G::generator().into_affine();
        let mut point_bytes = Vec::new();
        generator
            .serialize_compressed(&mut point_bytes)
            .expect("serialize generator");
        let sec1_bytes = point_to_sec1_for_curve(&point_bytes, curve_name).expect("convert point");
        assert_eq!(sec1_bytes.len(), 33);
        assert!(matches!(sec1_bytes[0], 0x02 | 0x03));
    }
}
