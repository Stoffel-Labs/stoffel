//! Helpers for loading SDK inputs from small data files.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};
use crate::types::Value;

/// Load named function inputs from a `.json`, `.csv`, or `.txt` file.
///
/// JSON files must contain an object such as `{"a": 40, "b": 2}`. CSV files
/// use the header row as input names and the first data row as values. TXT
/// files use one `name=value` assignment per line; blank lines and `#` comments
/// are ignored.
pub fn load_named_inputs_file(path: impl AsRef<Path>) -> Result<Vec<(String, Value)>> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)?;
    match file_extension(path)?.as_str() {
        "json" => load_named_inputs_json(&raw, path),
        "csv" => load_named_inputs_csv(&raw, path),
        "txt" => load_named_inputs_txt(&raw, path),
        extension => Err(Error::InvalidInput(format!(
            "unsupported input file extension '.{extension}' for {}; expected .json, .csv, or .txt",
            path.display()
        ))),
    }
}

/// Load local ClientStore inputs from a `.json`, `.csv`, or `.txt` file.
///
/// JSON files must contain an object keyed by numeric client slot, for example
/// `{"0": [40, 2]}`. CSV files must have `slot,value` or
/// `client_slot,value` headers. TXT files use one `slot=value` assignment per
/// line; repeated slots append values in file order.
pub fn load_client_inputs_file(path: impl AsRef<Path>) -> Result<Vec<(u64, Vec<Value>)>> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)?;
    match file_extension(path)?.as_str() {
        "json" => load_client_inputs_json(&raw, path),
        "csv" => load_client_inputs_csv(&raw, path),
        "txt" => load_client_inputs_txt(&raw, path),
        extension => Err(Error::InvalidInput(format!(
            "unsupported client input file extension '.{extension}' for {}; expected .json, .csv, or .txt",
            path.display()
        ))),
    }
}

fn file_extension(path: &Path) -> Result<String> {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "{} has no extension; expected .json, .csv, or .txt",
                path.display()
            ))
        })
}

fn load_named_inputs_json(raw: &str, path: &Path) -> Result<Vec<(String, Value)>> {
    let value = parse_json(raw, path)?;
    let serde_json::Value::Object(fields) = value else {
        return Err(Error::InvalidInput(format!(
            "{} must contain a JSON object of named inputs",
            path.display()
        )));
    };
    fields
        .into_iter()
        .map(|(name, value)| json_value_to_value(value).map(|value| (name, value)))
        .collect()
}

fn load_named_inputs_csv(raw: &str, path: &Path) -> Result<Vec<(String, Value)>> {
    let mut reader = csv::Reader::from_reader(raw.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| {
            Error::InvalidInput(format!("failed to parse {}: {error}", path.display()))
        })?
        .iter()
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if headers.is_empty() || headers.iter().any(|header| header.is_empty()) {
        return Err(Error::InvalidInput(format!(
            "{} CSV input file must include non-empty column headers",
            path.display()
        )));
    }
    let Some(record) = reader.records().next().transpose().map_err(|error| {
        Error::InvalidInput(format!("failed to parse {}: {error}", path.display()))
    })?
    else {
        return Err(Error::InvalidInput(format!(
            "{} CSV input file must include one data row",
            path.display()
        )));
    };
    if record.len() != headers.len() {
        return Err(Error::InvalidInput(format!(
            "{} CSV input row has {} value(s), but header has {} column(s)",
            path.display(),
            record.len(),
            headers.len()
        )));
    }
    headers
        .into_iter()
        .zip(record.iter())
        .map(|(name, raw)| parse_scalar_or_json(raw).map(|value| (name, value)))
        .collect()
}

fn load_named_inputs_txt(raw: &str, path: &Path) -> Result<Vec<(String, Value)>> {
    let mut inputs = Vec::new();
    for (line_index, line) in input_lines(raw).into_iter().enumerate() {
        let (name, value) = line.split_once('=').ok_or_else(|| {
            Error::InvalidInput(format!(
                "{}:{} must be written as name=value",
                path.display(),
                line_index + 1
            ))
        })?;
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::InvalidInput(format!(
                "{}:{} input name cannot be empty",
                path.display(),
                line_index + 1
            )));
        }
        inputs.push((name.to_owned(), parse_scalar_or_json(value.trim())?));
    }
    Ok(inputs)
}

fn load_client_inputs_json(raw: &str, path: &Path) -> Result<Vec<(u64, Vec<Value>)>> {
    let value = parse_json(raw, path)?;
    let serde_json::Value::Object(fields) = value else {
        return Err(Error::InvalidInput(format!(
            "{} must contain a JSON object keyed by numeric client slot",
            path.display()
        )));
    };
    let mut grouped = BTreeMap::<u64, Vec<Value>>::new();
    for (slot, value) in fields {
        let slot = parse_client_slot(&slot, path)?;
        append_client_value(&mut grouped, slot, json_value_to_value(value)?);
    }
    Ok(grouped.into_iter().collect())
}

fn load_client_inputs_csv(raw: &str, path: &Path) -> Result<Vec<(u64, Vec<Value>)>> {
    let mut reader = csv::Reader::from_reader(raw.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| {
            Error::InvalidInput(format!("failed to parse {}: {error}", path.display()))
        })?
        .iter()
        .map(|header| header.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let slot_index = headers
        .iter()
        .position(|header| header == "slot" || header == "client_slot")
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "{} client CSV input file must include a slot or client_slot column",
                path.display()
            ))
        })?;
    let value_index = headers
        .iter()
        .position(|header| header == "value")
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "{} client CSV input file must include a value column",
                path.display()
            ))
        })?;
    let mut grouped = BTreeMap::<u64, Vec<Value>>::new();
    for record in reader.records() {
        let record = record.map_err(|error| {
            Error::InvalidInput(format!("failed to parse {}: {error}", path.display()))
        })?;
        let slot = record.get(slot_index).unwrap_or("").trim();
        let value = record.get(value_index).unwrap_or("").trim();
        let slot = parse_client_slot(slot, path)?;
        append_client_value(&mut grouped, slot, parse_scalar_or_json(value)?);
    }
    Ok(grouped.into_iter().collect())
}

fn load_client_inputs_txt(raw: &str, path: &Path) -> Result<Vec<(u64, Vec<Value>)>> {
    let mut grouped = BTreeMap::<u64, Vec<Value>>::new();
    for (line_index, line) in input_lines(raw).into_iter().enumerate() {
        let (slot, value) = line.split_once('=').ok_or_else(|| {
            Error::InvalidInput(format!(
                "{}:{} must be written as slot=value",
                path.display(),
                line_index + 1
            ))
        })?;
        let slot = parse_client_slot(slot.trim(), path)?;
        append_client_value(&mut grouped, slot, parse_scalar_or_json(value.trim())?);
    }
    Ok(grouped.into_iter().collect())
}

fn input_lines(raw: &str) -> Vec<&str> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn parse_json(raw: &str, path: &Path) -> Result<serde_json::Value> {
    serde_json::from_str(raw).map_err(|error| {
        Error::InvalidInput(format!(
            "failed to parse JSON input file {}: {error}",
            path.display()
        ))
    })
}

fn parse_client_slot(raw: &str, path: &Path) -> Result<u64> {
    raw.parse::<u64>().map_err(|error| {
        Error::InvalidInput(format!(
            "invalid client slot '{raw}' in {}: {error}",
            path.display()
        ))
    })
}

fn append_client_value(grouped: &mut BTreeMap<u64, Vec<Value>>, slot: u64, value: Value) {
    match value {
        Value::List(values) => grouped.entry(slot).or_default().extend(values),
        value => grouped.entry(slot).or_default().push(value),
    }
}

fn json_value_to_value(value: serde_json::Value) -> Result<Value> {
    match value {
        serde_json::Value::Null => Ok(Value::Unit),
        serde_json::Value::Bool(value) => Ok(Value::Bool(value)),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                Ok(Value::I64(value))
            } else if let Some(value) = number.as_u64() {
                Ok(Value::U64(value))
            } else if let Some(value) = number.as_f64() {
                Ok(Value::Float(value))
            } else {
                Err(Error::InvalidInput(format!(
                    "unsupported JSON number '{number}'"
                )))
            }
        }
        serde_json::Value::String(value) => Ok(Value::String(value)),
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(json_value_to_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::List),
        serde_json::Value::Object(fields) => fields
            .into_iter()
            .map(|(key, value)| json_value_to_value(value).map(|value| (key, value)))
            .collect::<Result<BTreeMap<_, _>>>()
            .map(Value::Object),
    }
}

fn parse_scalar_or_json(raw: &str) -> Result<Value> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::InvalidInput(
            "input value cannot be empty".to_owned(),
        ));
    }
    if raw.starts_with('[') || raw.starts_with('{') || raw.starts_with('"') {
        return serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|error| {
                Error::InvalidInput(format!("invalid structured input '{raw}': {error}"))
            })
            .and_then(json_value_to_value);
    }
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return parse_hex_bytes(hex).map(Value::Bytes);
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Ok(Value::I64(value));
    }
    if let Ok(value) = raw.parse::<u64>() {
        return Ok(Value::U64(value));
    }
    if let Ok(value) = raw.parse::<bool>() {
        return Ok(Value::Bool(value));
    }
    if let Ok(value) = raw.parse::<f64>() {
        return Ok(Value::Float(value));
    }
    Ok(Value::String(raw.to_owned()))
}

fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(Error::InvalidInput(
            "hex byte input must contain an even number of digits".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut index = 0;
    while index < hex.len() {
        let pair = &hex[index..index + 2];
        let byte = u8::from_str_radix(pair, 16).map_err(|_| {
            Error::InvalidInput(format!("hex byte input contains invalid digits '{pair}'"))
        })?;
        bytes.push(byte);
        index += 2;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_named_inputs_preserve_keys_and_values() {
        let temp = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        std::fs::write(temp.path(), r#"{"a": 40, "b": true, "items": [1, 2]}"#).unwrap();

        let inputs = load_named_inputs_file(temp.path()).unwrap();

        assert_eq!(
            inputs,
            vec![
                ("a".to_owned(), Value::I64(40)),
                ("b".to_owned(), Value::Bool(true)),
                (
                    "items".to_owned(),
                    Value::List(vec![Value::I64(1), Value::I64(2)])
                ),
            ]
        );
    }

    #[test]
    fn csv_named_inputs_use_headers_and_first_row() {
        let temp = tempfile::NamedTempFile::with_suffix(".csv").unwrap();
        std::fs::write(temp.path(), "a,b,label\n40,2,hello\n").unwrap();

        let inputs = load_named_inputs_file(temp.path()).unwrap();

        assert_eq!(
            inputs,
            vec![
                ("a".to_owned(), Value::I64(40)),
                ("b".to_owned(), Value::I64(2)),
                ("label".to_owned(), Value::String("hello".to_owned())),
            ]
        );
    }

    #[test]
    fn txt_client_inputs_group_repeated_slots() {
        let temp = tempfile::NamedTempFile::with_suffix(".txt").unwrap();
        std::fs::write(temp.path(), "# comment\n0=40\n0=2\n1=true\n").unwrap();

        let inputs = load_client_inputs_file(temp.path()).unwrap();

        assert_eq!(
            inputs,
            vec![
                (0, vec![Value::I64(40), Value::I64(2)]),
                (1, vec![Value::Bool(true)]),
            ]
        );
    }
}
