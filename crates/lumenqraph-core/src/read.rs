//! The read layer: invoke a contract's **view functions** read-only and get a
//! typed result back — Soroban's answer to EVM `eth_call`.
//!
//! Soroban RPC's `simulateTransaction` can execute a contract invocation without
//! submitting it, returning the function's result. The friction is that you have
//! to hand-build a transaction envelope and encode/decode XDR. This module does
//! both, driven by the contract's on-chain spec (see [`crate::spec`]): given a
//! function name and JSON arguments, it type-checks and encodes the arguments
//! into `ScVal`s, wraps them in a simulation transaction, and hands back the
//! base64 XDR to simulate. Decoding the result reuses the event decoder.
//!
//! The network round-trip itself lives in the API service; everything here is
//! pure and unit-tested.

use std::str::FromStr;

use serde_json::Value;
use stellar_xdr::curr::{
    ContractEventBody, ContractEventType, DiagnosticEvent, HostFunction, Int128Parts, Int256Parts,
    InvokeContractArgs, InvokeHostFunctionOp, Limited, Limits, Memo, MuxedAccount, Operation,
    OperationBody, Preconditions, PublicKey, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry,
    ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef, ScString, ScSymbol, ScVal, ScVec, SequenceNumber,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, UInt128Parts,
    UInt256Parts, Uint256, VecM, WriteXdr,
};

use crate::spec::type_name;
use crate::ContractSpec;

/// The canonical all-zero account, used as the (never-signed, never-charged)
/// source of a simulation transaction when the caller supplies none.
const ZERO_ACCOUNT: Uint256 = Uint256([0u8; 32]);

/// An error encoding a read call — all client-fixable (bad/missing args, wrong
/// type, unknown function), so the API maps these to `400`.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("contract has no function named {0:?}")]
    FunctionNotFound(String),
    #[error("missing argument {0:?}")]
    MissingArgument(String),
    #[error("argument {name:?}: {msg}")]
    BadArgument { name: String, msg: String },
    #[error("argument {name:?}: type {ty} is not yet supported by the read layer")]
    UnsupportedType { name: String, ty: String },
    #[error("could not build simulation transaction: {0}")]
    Build(String),
}

/// A ready-to-simulate call: the base64 transaction envelope plus the declared
/// return type, so the result can be labelled once decoded.
#[derive(Debug)]
pub struct EncodedCall {
    pub tx_xdr: String,
    pub output_type: String,
    /// The structured form of `output_type`, kept so [`decode_result`] can name
    /// user-defined values in the result. `None` for a void function.
    pub output_ty: Option<ScSpecTypeDef>,
}

/// Encode a typed contract read into a simulation transaction.
///
/// `spec_section` is the raw `contractspecv0` XDR (as captured at index time).
/// `args` is either a JSON object keyed by parameter name, or a positional JSON
/// array. `source_account` is an optional `G…` or `M…` strkey to use as the tx
/// source (defaults to the zero account, which simulation accepts for read-only
/// calls). Both plain Ed25519 public keys (`G…`) and muxed accounts (`M…`) are
/// accepted.
pub fn encode_call(
    spec_section: &[u8],
    contract_id: &str,
    function: &str,
    args: &Value,
    source_account: Option<&str>,
) -> Result<EncodedCall, EncodeError> {
    // Parsed once and threaded through encoding: a `Udt` type is just a *name*,
    // so resolving it to its struct/union/enum definition needs the whole spec.
    let entries = parse_entries(spec_section);
    let func = find_function(&entries, function)
        .ok_or_else(|| EncodeError::FunctionNotFound(function.to_string()))?;

    let mut scvals: Vec<ScVal> = Vec::with_capacity(func.inputs.len());
    for (i, input) in func.inputs.iter().enumerate() {
        let name = input.name.to_utf8_string_lossy();
        let jv = match args {
            Value::Object(m) => m.get(&name),
            Value::Array(a) => a.get(i),
            _ => None,
        }
        .ok_or_else(|| EncodeError::MissingArgument(name.clone()))?;
        scvals.push(json_to_scval(jv, &input.type_, &name, &entries)?);
    }

    let output_ty = func.outputs.first().cloned();
    let output_type = output_ty
        .as_ref()
        .map(type_name)
        .unwrap_or_else(|| "void".to_string());

    let tx_xdr = build_read_tx(contract_id, function, scvals, source_account)
        .map_err(|e| EncodeError::Build(e.to_string()))?;
    Ok(EncodedCall {
        tx_xdr,
        output_type,
        output_ty,
    })
}

/// Name prefixes conventionally used by state-changing Soroban functions.
/// Soroban's `contractspecv0` carries no `view`/`mutable` keyword (unlike
/// Solidity), so this is the naming half of the `is_view` heuristic — best
/// effort, not a guarantee.
const MUTATING_PREFIXES: &[&str] = &[
    "set_", "init", "mint", "burn", "transfer", "approve", "withdraw", "deposit",
    "pause", "unpause", "upgrade", "admin_", "remove_", "add_", "create_", "delete_",
    "update_", "cancel", "claim", "deploy", "revoke", "grant", "lock", "unlock",
];

/// Best-effort guess at whether a function is read-only (safe via `/call`) or
/// state-changing (only safe via `/simulate`). Soroban's `contractspecv0` has
/// no `view` keyword, so this combines two weak signals: a `void` return type
/// almost always means the function mutates state (a pure read has something
/// to return), and a name matching a well-known mutating prefix.
fn is_view_heuristic(f: &ScSpecFunctionV0) -> bool {
    let is_void_output = f.outputs.is_empty();
    let name = f.name.to_utf8_string_lossy().to_lowercase();
    let matches_mutating_prefix = MUTATING_PREFIXES.iter().any(|p| name.starts_with(p));
    !is_void_output && !matches_mutating_prefix
}

/// List a contract's callable functions (name, typed inputs, output type),
/// derived from the raw spec section. Handy for a `/functions` endpoint.
///
/// Each entry also carries a best-effort `is_view` indicator (see
/// [`is_view_heuristic`]) — callers wanting to avoid accidental state
/// mutations should still prefer `/simulate` over `/call` when in doubt.
pub fn functions(spec_section: &[u8]) -> Vec<Value> {
    parse_entries(spec_section)
        .into_iter()
        .filter_map(|e| match e {
            ScSpecEntry::FunctionV0(f) => Some(serde_json::json!({
                "name": f.name.to_utf8_string_lossy(),
                "inputs": f.inputs.iter().map(|i| serde_json::json!({
                    "name": i.name.to_utf8_string_lossy(),
                    "type": type_name(&i.type_),
                })).collect::<Vec<_>>(),
                "outputs": f.outputs.iter().map(type_name).collect::<Vec<_>>(),
                "is_view": is_view_heuristic(&f),
            })),
            _ => None,
        })
        .collect()
}

fn parse_entries(spec_section: &[u8]) -> Vec<ScSpecEntry> {
    let mut limited = Limited::new(spec_section, Limits::none());
    ScSpecEntry::read_xdr_iter(&mut limited)
        .filter_map(Result::ok)
        .collect()
}

fn find_function(entries: &[ScSpecEntry], function: &str) -> Option<ScSpecFunctionV0> {
    entries.iter().find_map(|e| match e {
        ScSpecEntry::FunctionV0(f) if f.name.to_utf8_string_lossy() == function => Some(f.clone()),
        _ => None,
    })
}

/// Convert one JSON argument into an `ScVal` according to its declared type.
///
/// `entries` is the contract's full spec, needed to resolve `Udt` types (which
/// carry only a name) to their struct/union/enum definitions.
fn json_to_scval(
    v: &Value,
    ty: &ScSpecTypeDef,
    name: &str,
    entries: &[ScSpecEntry],
) -> Result<ScVal, EncodeError> {
    use ScSpecTypeDef as T;
    let bad = |msg: &str| EncodeError::BadArgument {
        name: name.to_string(),
        msg: msg.to_string(),
    };
    let unsupported = || EncodeError::UnsupportedType {
        name: name.to_string(),
        ty: type_name(ty),
    };

    Ok(match ty {
        T::Bool => ScVal::Bool(v.as_bool().ok_or_else(|| bad("expected a boolean"))?),
        T::U32 => ScVal::U32(int::<u32>(v, name)?),
        T::I32 => ScVal::I32(int::<i32>(v, name)?),
        T::U64 => ScVal::U64(int::<u64>(v, name)?),
        T::I64 => ScVal::I64(int::<i64>(v, name)?),
        T::Timepoint => ScVal::Timepoint(int::<u64>(v, name)?.into()),
        T::Duration => ScVal::Duration(int::<u64>(v, name)?.into()),
        T::U128 => ScVal::U128(u128_parts(int::<u128>(v, name)?)),
        T::I128 => ScVal::I128(i128_parts(int::<i128>(v, name)?)),
        T::Symbol => ScVal::Symbol(ScSymbol(
            str_of(v, name)?
                .try_into()
                .map_err(|_| bad("symbol too long or invalid"))?,
        )),
        T::String => ScVal::String(ScString(
            str_of(v, name)?
                .try_into()
                .map_err(|_| bad("string too long"))?,
        )),
        T::Address => ScVal::Address(
            ScAddress::from_str(str_of(v, name)?).map_err(|_| bad("invalid address strkey"))?,
        ),
        T::Bytes => ScVal::Bytes(ScBytes(
            decode_hex(v, name)?
                .try_into()
                .map_err(|_| bad("byte string too long"))?,
        )),
        T::BytesN(n) => {
            let bytes = decode_hex(v, name)?;
            if bytes.len() != n.n as usize {
                return Err(bad(&format!("expected {} bytes", n.n)));
            }
            ScVal::Bytes(ScBytes(
                bytes.try_into().map_err(|_| bad("byte string too long"))?,
            ))
        }
        T::Option(inner) => {
            if v.is_null() {
                ScVal::Void
            } else {
                json_to_scval(v, &inner.value_type, name, entries)?
            }
        }
        T::Vec(inner) => {
            let arr = v.as_array().ok_or_else(|| bad("expected an array"))?;
            let items: Result<Vec<ScVal>, _> = arr
                .iter()
                .map(|el| json_to_scval(el, &inner.element_type, name, entries))
                .collect();
            ScVal::Vec(Some(ScVec(vecm(items?, name)?)))
        }
        T::Tuple(t) => {
            let arr = v.as_array().ok_or_else(|| bad("expected a tuple array"))?;
            if arr.len() != t.value_types.len() {
                return Err(bad(&format!(
                    "expected {} tuple elements",
                    t.value_types.len()
                )));
            }
            let items: Result<Vec<ScVal>, _> = arr
                .iter()
                .zip(t.value_types.iter())
                .map(|(el, et)| json_to_scval(el, et, name, entries))
                .collect();
            ScVal::Vec(Some(ScVec(vecm(items?, name)?)))
        }
        T::Map(m) => {
            // Only symbol/string-keyed maps map cleanly from a JSON object.
            // serde_json orders object keys, which is also what ScMap requires.
            let obj = v.as_object().ok_or_else(|| bad("expected an object"))?;
            let mut items = Vec::with_capacity(obj.len());
            for (k, val) in obj {
                let key = json_to_scval(&Value::String(k.clone()), &m.key_type, name, entries)?;
                let val = json_to_scval(val, &m.value_type, name, entries)?;
                items.push(ScMapEntry { key, val });
            }
            ScVal::Map(Some(ScMap(vecm(items, name)?)))
        }
        T::U256 => ScVal::U256(u256_parts(parse_u256(v, name)?)),
        T::I256 => ScVal::I256(i256_parts(parse_i256(v, name)?)),
        T::Void => {
            if !v.is_null() {
                return Err(bad("expected null"));
            }
            ScVal::Void
        }
        T::Udt(u) => udt_to_scval(v, &u.name.to_utf8_string_lossy(), name, entries)?,
        // `Val` is untyped by definition, and Result/Error/MuxedAddress aren't
        // things a view function takes as input in practice. Left as a clear
        // client error rather than a guess.
        //
        // Note: MuxedAccount (M… strkey) *is* supported as the `source_account`
        // argument to `/call` and `/simulate`, but not as a typed function
        // parameter in the contract spec.
        T::Val | T::Result(_) | T::Error | T::MuxedAddress => {
            return Err(unsupported());
        }
    })
}

/// Encode a JSON value as a user-defined type, resolved by name from the spec.
///
/// The three UDT shapes have distinct on-chain encodings, mirroring how
/// `soroban-sdk` derives them:
///   - struct with named fields -> `ScMap` keyed by field-name symbols
///   - struct with numeric field names (a tuple struct) -> `ScVec` of values
///   - unit enum -> `ScVal::U32` of the case's declared value
///   - union -> `ScVec` of `[Symbol(case), ..values]`
fn udt_to_scval(
    v: &Value,
    udt_name: &str,
    arg: &str,
    entries: &[ScSpecEntry],
) -> Result<ScVal, EncodeError> {
    let bad = |msg: String| EncodeError::BadArgument {
        name: arg.to_string(),
        msg,
    };

    for entry in entries {
        match entry {
            ScSpecEntry::UdtStructV0(s) if s.name.to_utf8_string_lossy() == udt_name => {
                return struct_to_scval(v, s, arg, entries);
            }
            ScSpecEntry::UdtEnumV0(e) if e.name.to_utf8_string_lossy() == udt_name => {
                return enum_to_scval(v, e, arg);
            }
            ScSpecEntry::UdtUnionV0(u) if u.name.to_utf8_string_lossy() == udt_name => {
                return union_to_scval(v, u, arg, entries);
            }
            _ => {}
        }
    }
    // The spec referenced a type it doesn't define — a malformed/truncated spec
    // section rather than a caller mistake, but there's nothing to encode against.
    Err(bad(format!(
        "contract spec references unknown type {udt_name:?}"
    )))
}

fn struct_to_scval(
    v: &Value,
    s: &stellar_xdr::curr::ScSpecUdtStructV0,
    arg: &str,
    entries: &[ScSpecEntry],
) -> Result<ScVal, EncodeError> {
    let bad = |msg: String| EncodeError::BadArgument {
        name: arg.to_string(),
        msg,
    };
    let field_names: Vec<String> = s
        .fields
        .iter()
        .map(|f| f.name.to_utf8_string_lossy())
        .collect();

    // soroban-sdk names tuple-struct fields "0", "1", … and encodes them
    // positionally; a struct with real field names becomes a map.
    let is_tuple = !field_names.is_empty()
        && field_names
            .iter()
            .all(|n| n.chars().all(|c| c.is_ascii_digit()));

    if is_tuple {
        let arr = v
            .as_array()
            .ok_or_else(|| bad(format!("expected an array for tuple struct {:?}", s.name)))?;
        if arr.len() != s.fields.len() {
            return Err(bad(format!(
                "expected {} elements for tuple struct {:?}, got {}",
                s.fields.len(),
                s.name,
                arr.len()
            )));
        }
        let items: Result<Vec<ScVal>, _> = arr
            .iter()
            .zip(s.fields.iter())
            .map(|(el, f)| json_to_scval(el, &f.type_, arg, entries))
            .collect();
        return Ok(ScVal::Vec(Some(ScVec(vecm(items?, arg)?))));
    }

    let obj = v
        .as_object()
        .ok_or_else(|| bad(format!("expected an object for struct {:?}", s.name)))?;
    let mut items = Vec::with_capacity(s.fields.len());
    for f in s.fields.iter() {
        let fname = f.name.to_utf8_string_lossy();
        let fv = obj
            .get(&fname)
            .ok_or_else(|| bad(format!("missing field {fname:?} of struct {:?}", s.name)))?;
        items.push(ScMapEntry {
            key: ScVal::Symbol(ScSymbol(
                fname
                    .clone()
                    .try_into()
                    .map_err(|_| bad(format!("field name {fname:?} is not a valid symbol")))?,
            )),
            val: json_to_scval(fv, &f.type_, arg, entries)?,
        });
    }
    // ScMap must be key-sorted; spec field order is declaration order.
    items.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(ScVal::Map(Some(ScMap(vecm(items, arg)?))))
}

fn enum_to_scval(
    v: &Value,
    e: &stellar_xdr::curr::ScSpecUdtEnumV0,
    arg: &str,
) -> Result<ScVal, EncodeError> {
    let bad = |msg: String| EncodeError::BadArgument {
        name: arg.to_string(),
        msg,
    };
    let names = || {
        e.cases
            .iter()
            .map(|c| c.name.to_utf8_string_lossy())
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Accept the case name (friendly) or its raw discriminant (what you'd see
    // in decoded output), but validate either against the spec.
    if let Some(s) = v.as_str() {
        let case = e
            .cases
            .iter()
            .find(|c| c.name.to_utf8_string_lossy() == s)
            .ok_or_else(|| {
                bad(format!(
                    "unknown case {s:?} for enum {:?}; expected one of: {}",
                    e.name,
                    names()
                ))
            })?;
        return Ok(ScVal::U32(case.value));
    }
    if let Some(n) = v.as_u64() {
        let value = u32::try_from(n)
            .map_err(|_| bad(format!("{n} is out of range for enum {:?}", e.name)))?;
        if !e.cases.iter().any(|c| c.value == value) {
            return Err(bad(format!(
                "{value} is not a declared value of enum {:?}; expected one of: {}",
                e.name,
                names()
            )));
        }
        return Ok(ScVal::U32(value));
    }
    Err(bad(format!(
        "expected a case name or value for enum {:?}; expected one of: {}",
        e.name,
        names()
    )))
}

fn union_to_scval(
    v: &Value,
    u: &stellar_xdr::curr::ScSpecUdtUnionV0,
    arg: &str,
    entries: &[ScSpecEntry],
) -> Result<ScVal, EncodeError> {
    use stellar_xdr::curr::ScSpecUdtUnionCaseV0 as Case;
    let bad = |msg: String| EncodeError::BadArgument {
        name: arg.to_string(),
        msg,
    };
    let case_name = |c: &Case| match c {
        Case::VoidV0(x) => x.name.to_utf8_string_lossy(),
        Case::TupleV0(x) => x.name.to_utf8_string_lossy(),
    };
    let names = || u.cases.iter().map(case_name).collect::<Vec<_>>().join(", ");
    let find = |want: &str| u.cases.iter().find(|c| case_name(c) == want).cloned();
    let symbol = |s: &str| -> Result<ScVal, EncodeError> {
        Ok(ScVal::Symbol(ScSymbol(s.to_string().try_into().map_err(
            |_| bad(format!("case name {s:?} is not a valid symbol")),
        )?)))
    };

    // A bare string selects a void case: "Active".
    if let Some(s) = v.as_str() {
        return match find(s) {
            Some(Case::VoidV0(_)) => Ok(ScVal::Vec(Some(ScVec(vecm(vec![symbol(s)?], arg)?)))),
            Some(Case::TupleV0(t)) => Err(bad(format!(
                "case {s:?} of union {:?} carries {} value(s); pass {{\"{s}\": [..]}}",
                u.name,
                t.type_.len()
            ))),
            None => Err(bad(format!(
                "unknown case {s:?} for union {:?}; expected one of: {}",
                u.name,
                names()
            ))),
        };
    }

    // Otherwise a single-key object selects a tuple case: {"Bid": [addr, 100]}.
    let obj = v.as_object().ok_or_else(|| {
        bad(format!(
            "expected a case name or {{case: value}} for union {:?}; expected one of: {}",
            u.name,
            names()
        ))
    })?;
    if obj.len() != 1 {
        return Err(bad(format!(
            "expected exactly one case for union {:?}, got {} keys",
            u.name,
            obj.len()
        )));
    }
    // SAFETY: we verified obj.len() == 1 two lines above; this cannot be None.
    #[allow(clippy::expect_used)]
    let (key, val) = obj.iter().next().expect("len checked above");
    match find(key) {
        Some(Case::VoidV0(_)) => {
            if !val.is_null() {
                return Err(bad(format!(
                    "case {key:?} of union {:?} carries no value",
                    u.name
                )));
            }
            Ok(ScVal::Vec(Some(ScVec(vecm(vec![symbol(key)?], arg)?))))
        }
        Some(Case::TupleV0(t)) => {
            // One-value cases may be written unwrapped: {"Bid": 100}.
            let owned;
            let vals: &[Value] = match val.as_array() {
                Some(a) => a,
                None if t.type_.len() == 1 => {
                    owned = [val.clone()];
                    &owned
                }
                None => {
                    return Err(bad(format!(
                        "expected an array of {} values for case {key:?}",
                        t.type_.len()
                    )))
                }
            };
            if vals.len() != t.type_.len() {
                return Err(bad(format!(
                    "case {key:?} of union {:?} expects {} value(s), got {}",
                    u.name,
                    t.type_.len(),
                    vals.len()
                )));
            }
            let mut items = vec![symbol(key)?];
            for (el, et) in vals.iter().zip(t.type_.iter()) {
                items.push(json_to_scval(el, et, arg, entries)?);
            }
            Ok(ScVal::Vec(Some(ScVec(vecm(items, arg)?))))
        }
        None => Err(bad(format!(
            "unknown case {key:?} for union {:?}; expected one of: {}",
            u.name,
            names()
        ))),
    }
}

/// Parse a `G…` or `M…` strkey into a `MuxedAccount` for use as a simulation
/// transaction source.
///
/// - `G…` (StrKey Ed25519 public key) → `MuxedAccount::Ed25519`
/// - `M…` (StrKey muxed account)      → `MuxedAccount::MuxedEd25519`
///
/// Any other format is rejected by the underlying XDR parser and surfaced as
/// a `Build` error to the caller.
fn parse_source_account(s: &str) -> Result<MuxedAccount, stellar_xdr::curr::Error> {
    // Try muxed account first (M… prefix); fall back to plain G… public key.
    if s.starts_with('M') {
        MuxedAccount::from_str(s)
    } else {
        match PublicKey::from_str(s)? {
            PublicKey::PublicKeyTypeEd25519(k) => Ok(MuxedAccount::Ed25519(k)),
        }
    }
}

fn build_read_tx(
    contract_id: &str,
    function: &str,
    args: Vec<ScVal>,
    source_account: Option<&str>,
) -> Result<String, stellar_xdr::curr::Error> {
    let source = match source_account {
        Some(s) => parse_source_account(s)?,
        None => MuxedAccount::Ed25519(ZERO_ACCOUNT),
    };

    let invoke = InvokeContractArgs {
        contract_address: ScAddress::from_str(contract_id)?,
        function_name: ScSymbol(function.try_into()?),
        args: args.try_into()?,
    };
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke),
            auth: VecM::default(),
        }),
    };
    let tx = Transaction {
        source_account: source,
        fee: 0,
        seq_num: SequenceNumber(0),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op].try_into()?,
        // V0: no Soroban footprint attached — RPC's preflight computes it.
        ext: TransactionExt::V0,
    };
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    envelope.to_xdr_base64(Limits::none())
}

/// Decode a simulation's base64 `ScVal` result and label it with its type.
///
/// With the parsed spec in hand, user-defined values in the result are *named*:
/// an enum discriminant becomes its case name, a union becomes `{Case: [..]}` —
/// the same shapes [`encode_call`] accepts as arguments, so results can be fed
/// straight back into another call.
pub fn decode_result(result_xdr: &str, call: &EncodedCall, spec: Option<&ContractSpec>) -> Value {
    let mut value = crate::xdr::decode_scval_base64(result_xdr);
    if let (Some(spec), Some(ty)) = (spec, call.output_ty.as_ref()) {
        value = spec.relabel_value(&value, ty);
    }
    serde_json::json!({
        "type": call.output_type,
        "value": value,
    })
}

/// Decode the events a simulation reported. The low-level diagnostic trace
/// (`fn_call`/`fn_return`) is filtered out; the remaining contract and system
/// events are decoded like indexed events, and those emitted by
/// `target_contract` are enriched with its spec when one is supplied. This is
/// what makes `POST /contracts/:id/simulate` show "the events this call emits".
pub fn decode_events(
    events_xdr: &[String],
    target_contract: &str,
    spec: Option<&ContractSpec>,
) -> Vec<Value> {
    let mut out = Vec::new();
    for b64 in events_xdr {
        let Ok(diag) = DiagnosticEvent::from_xdr_base64(b64, Limits::none()) else {
            continue;
        };
        let event = diag.event;
        // Skip the fn_call/fn_return diagnostic trace — keep meaningful events.
        let kind = match event.type_ {
            ContractEventType::Contract => "contract",
            ContractEventType::System => "system",
            ContractEventType::Diagnostic => continue,
        };
        let ContractEventBody::V0(body) = event.body;
        let contract_id = event
            .contract_id
            .map(|c| ScAddress::Contract(c).to_string());
        let topics: Vec<Value> = body.topics.iter().map(scval_to_json).collect();
        let data = scval_to_json(&body.data);
        let event_name = topics.first().and_then(|t| t.as_str().map(String::from));

        // Enrich events emitted by the contract we're simulating.
        let enriched = match (spec, &event_name, &contract_id) {
            (Some(spec), Some(name), Some(cid)) if cid == target_contract => {
                spec.enrich_event(name, &topics, &data)
            }
            _ => None,
        };

        out.push(serde_json::json!({
            "contract_id": contract_id,
            "type": kind,
            "event": event_name,
            "topics": topics,
            "data": data,
            "enriched": enriched,
        }));
    }
    out
}

/// Decode an already-parsed `ScVal` to JSON by re-encoding it through the same
/// decoder events use (keeps one JSON shape across the whole system).
fn scval_to_json(sv: &ScVal) -> Value {
    match sv.to_xdr_base64(Limits::none()) {
        Ok(b64) => crate::xdr::decode_scval_base64(&b64),
        Err(_) => Value::Null,
    }
}

// ---- small helpers ----

fn str_of<'a>(v: &'a Value, name: &str) -> Result<&'a str, EncodeError> {
    v.as_str().ok_or_else(|| EncodeError::BadArgument {
        name: name.to_string(),
        msg: "expected a string".to_string(),
    })
}

/// Parse an integer argument from a JSON string or integral number, into any
/// integer type. Strings are required for values that exceed a JS-safe number.
fn int<T: FromStr>(v: &Value, name: &str) -> Result<T, EncodeError> {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
        _ => {
            return Err(EncodeError::BadArgument {
                name: name.to_string(),
                msg: "expected an integer (as a number or decimal string)".to_string(),
            })
        }
    };
    s.parse::<T>().map_err(|_| EncodeError::BadArgument {
        name: name.to_string(),
        msg: "integer out of range for this type".to_string(),
    })
}

fn decode_hex(v: &Value, name: &str) -> Result<Vec<u8>, EncodeError> {
    let s = str_of(v, name)?
        .strip_prefix("0x")
        .unwrap_or(str_of(v, name)?);
    hex::decode(s).map_err(|_| EncodeError::BadArgument {
        name: name.to_string(),
        msg: "expected a hex string".to_string(),
    })
}

fn vecm<U>(items: Vec<U>, name: &str) -> Result<VecM<U>, EncodeError> {
    items.try_into().map_err(|_| EncodeError::BadArgument {
        name: name.to_string(),
        msg: "too many elements".to_string(),
    })
}

// Slicing a fixed [u8; 16] into [u8; 8] halves is always in-bounds.
#[allow(clippy::unwrap_used)]
fn i128_parts(n: i128) -> Int128Parts {
    let b = n.to_be_bytes();
    Int128Parts {
        hi: i64::from_be_bytes(b[0..8].try_into().unwrap()),
        lo: u64::from_be_bytes(b[8..16].try_into().unwrap()),
    }
}

fn u128_parts(n: u128) -> UInt128Parts {
    UInt128Parts {
        hi: (n >> 64) as u64,
        lo: n as u64,
    }
}

// ---- 256-bit integers -------------------------------------------------------
//
// Rust has no u256/i256 and the crate carries no bignum dependency, so these
// work on four big-endian 64-bit limbs (index 0 = most significant), which is
// also exactly the shape `UInt256Parts`/`Int256Parts` want.

type Limbs = [u64; 4];

/// `limbs * 10 + digit`, or `None` on overflow past 256 bits.
fn mul10_add(limbs: Limbs, digit: u8) -> Option<Limbs> {
    let mut out = limbs;
    let mut carry = digit as u128;
    for i in (0..4).rev() {
        let acc = out[i] as u128 * 10 + carry;
        out[i] = acc as u64;
        carry = acc >> 64;
    }
    (carry == 0).then_some(out)
}

/// Two's-complement negation, for reading a negative i256 as a bit pattern.
fn negate(limbs: Limbs) -> Limbs {
    let mut out = limbs.map(|x| !x);
    let mut carry = 1u128;
    for i in (0..4).rev() {
        let acc = out[i] as u128 + carry;
        out[i] = acc as u64;
        carry = acc >> 64;
        if carry == 0 {
            break;
        }
    }
    out
}

/// Parse a decimal magnitude (no sign) into limbs.
fn parse_digits(s: &str, name: &str) -> Result<Limbs, EncodeError> {
    let bad = |msg: &str| EncodeError::BadArgument {
        name: name.to_string(),
        msg: msg.to_string(),
    };
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("expected a decimal integer"));
    }
    let mut limbs: Limbs = [0; 4];
    for b in s.bytes() {
        limbs =
            mul10_add(limbs, b - b'0').ok_or_else(|| bad("integer out of range for 256 bits"))?;
    }
    Ok(limbs)
}

/// A 256-bit value is beyond f64, so accept it as a decimal string; JSON numbers
/// are still allowed for the small values that survive the round-trip intact.
fn text_of_int(v: &Value, name: &str) -> Result<String, EncodeError> {
    match v {
        Value::String(s) => Ok(s.trim().to_string()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.to_string()),
        _ => Err(EncodeError::BadArgument {
            name: name.to_string(),
            msg: "expected a 256-bit integer as a decimal string".to_string(),
        }),
    }
}

fn parse_u256(v: &Value, name: &str) -> Result<Limbs, EncodeError> {
    let s = text_of_int(v, name)?;
    if s.starts_with('-') {
        return Err(EncodeError::BadArgument {
            name: name.to_string(),
            msg: "expected an unsigned integer".to_string(),
        });
    }
    parse_digits(s.strip_prefix('+').unwrap_or(&s), name)
}

fn parse_i256(v: &Value, name: &str) -> Result<Limbs, EncodeError> {
    let s = text_of_int(v, name)?;
    let bad = |msg: &str| EncodeError::BadArgument {
        name: name.to_string(),
        msg: msg.to_string(),
    };
    let negative = s.starts_with('-');
    let digits = s.strip_prefix(['-', '+']).unwrap_or(&s);
    let limbs = parse_digits(digits, name)?;

    // Signed range is [-2^255, 2^255-1]: the magnitude may reach 2^255 only when
    // negative, and that one value is its own negation.
    let top = limbs[0] & (1 << 63) != 0;
    let is_min = top && limbs[1..] == [0, 0, 0] && limbs[0] == 1 << 63;
    match (negative, top, is_min) {
        (false, true, _) => Err(bad("integer out of range for i256")),
        (true, true, false) => Err(bad("integer out of range for i256")),
        (true, _, _) => Ok(negate(limbs)),
        _ => Ok(limbs),
    }
}

fn u256_parts(l: Limbs) -> UInt256Parts {
    UInt256Parts {
        hi_hi: l[0],
        hi_lo: l[1],
        lo_hi: l[2],
        lo_lo: l[3],
    }
}

fn i256_parts(l: Limbs) -> Int256Parts {
    Int256Parts {
        hi_hi: l[0] as i64,
        hi_lo: l[1],
        lo_hi: l[2],
        lo_lo: l[3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSymbol, WriteXdr,
    };

    // balance(id: Address) -> i128
    fn balance_spec() -> Vec<u8> {
        let entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: "".try_into().unwrap(),
            name: ScSymbol("balance".try_into().unwrap()),
            inputs: vec![ScSpecFunctionInputV0 {
                doc: "".try_into().unwrap(),
                name: "id".try_into().unwrap(),
                type_: ScSpecTypeDef::Address,
            }]
            .try_into()
            .unwrap(),
            outputs: vec![ScSpecTypeDef::I128].try_into().unwrap(),
        });
        entry.to_xdr(Limits::none()).unwrap()
    }

    const G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const C: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    #[test]
    fn encodes_a_typed_call_and_round_trips() {
        let spec = balance_spec();
        let args = serde_json::json!({ "id": G });
        let call = encode_call(&spec, C, "balance", &args, None).expect("should encode");
        assert_eq!(call.output_type, "i128");

        // Decode the envelope back and check the invocation we built.
        let env = TransactionEnvelope::from_xdr_base64(&call.tx_xdr, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = env else {
            panic!("expected v1 envelope")
        };
        let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
            panic!("expected invoke host function")
        };
        let HostFunction::InvokeContract(ic) = &op.host_function else {
            panic!("expected invoke contract")
        };
        assert_eq!(ic.function_name.to_utf8_string_lossy(), "balance");
        assert_eq!(ic.args.len(), 1);
        assert!(matches!(ic.args[0], ScVal::Address(_)));
    }

    #[test]
    fn positional_args_work_too() {
        let spec = balance_spec();
        let call = encode_call(&spec, C, "balance", &serde_json::json!([G]), None);
        assert!(call.is_ok());
    }

    // A valid M-strkey: the minimal muxed-account encoding of the all-zero key
    // with sub-account id 0.
    const M: &str = "MA7QYNF7SOWQ3GLR2BGMZEHXR776WJRK76K2GS4K4BRZ4LHE4AAAAAAAAAAPCIBVZA";

    #[test]
    fn muxed_account_source_is_accepted() {
        let spec = balance_spec();
        let call = encode_call(&spec, C, "balance", &serde_json::json!({ "id": G }), Some(M))
            .expect("M-strkey source_account should be accepted");
        // Decode the envelope and verify the source is a MuxedEd25519 account.
        let env = TransactionEnvelope::from_xdr_base64(&call.tx_xdr, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = env else {
            panic!("expected v1 envelope")
        };
        assert!(
            matches!(v1.tx.source_account, MuxedAccount::MuxedEd25519(_)),
            "expected MuxedEd25519 source, got {:?}",
            v1.tx.source_account
        );
    }

    #[test]
    fn g_strkey_source_still_works() {
        let spec = balance_spec();
        let call = encode_call(&spec, C, "balance", &serde_json::json!({ "id": G }), Some(G))
            .expect("G-strkey source_account should still be accepted");
        let env = TransactionEnvelope::from_xdr_base64(&call.tx_xdr, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = env else {
            panic!("expected v1 envelope")
        };
        assert!(
            matches!(v1.tx.source_account, MuxedAccount::Ed25519(_)),
            "expected Ed25519 source, got {:?}",
            v1.tx.source_account
        );
    }

    #[test]
    fn invalid_source_account_is_a_build_error() {
        let spec = balance_spec();
        let err = encode_call(
            &spec,
            C,
            "balance",
            &serde_json::json!({ "id": G }),
            Some("not-a-strkey"),
        )
        .unwrap_err();
        assert!(matches!(err, EncodeError::Build(_)));
    }

    #[test]
    fn unknown_function_is_an_error() {
        let spec = balance_spec();
        let err = encode_call(&spec, C, "nope", &serde_json::json!({}), None).unwrap_err();
        assert!(matches!(err, EncodeError::FunctionNotFound(_)));
    }

    #[test]
    fn missing_argument_is_an_error() {
        let spec = balance_spec();
        let err = encode_call(&spec, C, "balance", &serde_json::json!({}), None).unwrap_err();
        assert!(matches!(err, EncodeError::MissingArgument(_)));
    }

    #[test]
    fn wrong_argument_type_is_an_error() {
        let spec = balance_spec();
        // an address arg given a non-strkey string
        let err = encode_call(
            &spec,
            C,
            "balance",
            &serde_json::json!({ "id": "nope" }),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, EncodeError::BadArgument { .. }));
    }

    #[test]
    fn decode_result_names_udt_values_with_the_spec() {
        use stellar_xdr::curr::{ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0};

        // enum Status { Active = 0, Filled = 7 }; status() -> Status
        let mut spec = Vec::new();
        spec.extend(
            ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
                doc: "".try_into().unwrap(),
                lib: "".try_into().unwrap(),
                name: "Status".try_into().unwrap(),
                cases: vec![
                    ScSpecUdtEnumCaseV0 {
                        doc: "".try_into().unwrap(),
                        name: "Active".try_into().unwrap(),
                        value: 0,
                    },
                    ScSpecUdtEnumCaseV0 {
                        doc: "".try_into().unwrap(),
                        name: "Filled".try_into().unwrap(),
                        value: 7,
                    },
                ]
                .try_into()
                .unwrap(),
            })
            .to_xdr(Limits::none())
            .unwrap(),
        );
        spec.extend(
            ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                doc: "".try_into().unwrap(),
                name: ScSymbol("status".try_into().unwrap()),
                inputs: vec![].try_into().unwrap(),
                outputs: vec![ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
                    name: "Status".try_into().unwrap(),
                })]
                .try_into()
                .unwrap(),
            })
            .to_xdr(Limits::none())
            .unwrap(),
        );

        let call = encode_call(&spec, C, "status", &serde_json::json!({}), None).unwrap();
        assert_eq!(call.output_type, "Status");
        let result_xdr = ScVal::U32(7).to_xdr_base64(Limits::none()).unwrap();

        // Without the spec the result is a meaningless discriminant…
        let raw = decode_result(&result_xdr, &call, None);
        assert_eq!(raw["value"], 7);

        // …with it, the case is named — in the shape the encoder accepts back.
        let parsed = ContractSpec::from_spec_xdr(&spec).unwrap();
        let named = decode_result(&result_xdr, &call, Some(&parsed));
        assert_eq!(named["value"], "Filled");
        assert_eq!(named["type"], "Status");
    }

    #[test]
    fn i128_splits_into_correct_parts() {
        // (hi << 64) | lo == value
        let p = i128_parts(105_000_000);
        assert_eq!(((p.hi as i128) << 64) | (p.lo as i128), 105_000_000);
        let neg = i128_parts(-5);
        assert_eq!(((neg.hi as i128) << 64) | (neg.lo as i128), -5);
    }

    #[test]
    fn functions_lists_the_interface() {
        let fns = functions(&balance_spec());
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0]["name"], "balance");
        assert_eq!(fns[0]["inputs"][0]["type"], "Address");
        assert_eq!(fns[0]["outputs"][0], "i128");
    }

    #[test]
    fn decodes_simulation_events_and_skips_diagnostics() {
        use stellar_xdr::curr::{
            ContractEvent, ContractEventBody, ContractEventType, ContractEventV0, ContractId,
            DiagnosticEvent, ExtensionPoint, Hash,
        };
        let sym = |s: &str| ScVal::Symbol(ScSymbol(s.try_into().unwrap()));
        let mk = |ty: ContractEventType, topic0: &str| {
            let ev = ContractEvent {
                ext: ExtensionPoint::V0,
                contract_id: Some(ContractId(Hash([7u8; 32]))),
                type_: ty,
                body: ContractEventBody::V0(ContractEventV0 {
                    topics: vec![sym(topic0)].try_into().unwrap(),
                    data: ScVal::I128(i128_parts(42)),
                }),
            };
            DiagnosticEvent {
                in_successful_contract_call: true,
                event: ev,
            }
            .to_xdr_base64(Limits::none())
            .unwrap()
        };

        let events = vec![
            mk(ContractEventType::Contract, "transfer"),
            mk(ContractEventType::Diagnostic, "fn_call"),
        ];
        let decoded = decode_events(&events, "CUNKNOWN", None);
        // The diagnostic trace event is filtered out.
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0]["type"], "contract");
        assert_eq!(decoded[0]["event"], "transfer");
        assert_eq!(decoded[0]["data"], "42");
        assert!(decoded[0]["contract_id"].as_str().unwrap().starts_with('C'));
    }

    // ---- user-defined types & 256-bit integers ------------------------------

    mod udt {
        use super::*;
        use serde_json::json;
        use stellar_xdr::curr::{
            ScSpecTypeUdt, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0, ScSpecUdtStructFieldV0,
            ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0,
            ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0,
        };

        fn udt(name: &str) -> ScSpecTypeDef {
            ScSpecTypeDef::Udt(ScSpecTypeUdt {
                name: name.try_into().unwrap(),
            })
        }

        fn field(name: &str, type_: ScSpecTypeDef) -> ScSpecUdtStructFieldV0 {
            ScSpecUdtStructFieldV0 {
                doc: "".try_into().unwrap(),
                name: name.try_into().unwrap(),
                type_,
            }
        }

        fn func(name: &str, inputs: Vec<(&str, ScSpecTypeDef)>) -> ScSpecEntry {
            ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                doc: "".try_into().unwrap(),
                name: ScSymbol(name.try_into().unwrap()),
                inputs: inputs
                    .into_iter()
                    .map(|(n, type_)| ScSpecFunctionInputV0 {
                        doc: "".try_into().unwrap(),
                        name: n.try_into().unwrap(),
                        type_,
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                outputs: vec![ScSpecTypeDef::Bool].try_into().unwrap(),
            })
        }

        /// A spec exercising every UDT shape:
        ///   struct Order { amount: i128, buyer: Address }   (named -> map)
        ///   struct Pair(u32, u32)                           (tuple -> vec)
        ///   enum Status { Active = 0, Filled = 7 }
        ///   union Action { Cancel, Bid(Address, i128) }
        fn spec() -> Vec<u8> {
            let entries = vec![
                ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
                    doc: "".try_into().unwrap(),
                    lib: "".try_into().unwrap(),
                    name: "Order".try_into().unwrap(),
                    // Declared amount-then-buyer; the encoder must sort the map.
                    fields: vec![
                        field("amount", ScSpecTypeDef::I128),
                        field("buyer", ScSpecTypeDef::Address),
                    ]
                    .try_into()
                    .unwrap(),
                }),
                ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
                    doc: "".try_into().unwrap(),
                    lib: "".try_into().unwrap(),
                    name: "Pair".try_into().unwrap(),
                    fields: vec![
                        field("0", ScSpecTypeDef::U32),
                        field("1", ScSpecTypeDef::U32),
                    ]
                    .try_into()
                    .unwrap(),
                }),
                ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
                    doc: "".try_into().unwrap(),
                    lib: "".try_into().unwrap(),
                    name: "Status".try_into().unwrap(),
                    cases: vec![
                        ScSpecUdtEnumCaseV0 {
                            doc: "".try_into().unwrap(),
                            name: "Active".try_into().unwrap(),
                            value: 0,
                        },
                        ScSpecUdtEnumCaseV0 {
                            doc: "".try_into().unwrap(),
                            name: "Filled".try_into().unwrap(),
                            value: 7,
                        },
                    ]
                    .try_into()
                    .unwrap(),
                }),
                ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
                    doc: "".try_into().unwrap(),
                    lib: "".try_into().unwrap(),
                    name: "Action".try_into().unwrap(),
                    cases: vec![
                        ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                            doc: "".try_into().unwrap(),
                            name: "Cancel".try_into().unwrap(),
                        }),
                        ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                            doc: "".try_into().unwrap(),
                            name: "Bid".try_into().unwrap(),
                            type_: vec![ScSpecTypeDef::Address, ScSpecTypeDef::I128]
                                .try_into()
                                .unwrap(),
                        }),
                    ]
                    .try_into()
                    .unwrap(),
                }),
                func("submit", vec![("order", udt("Order"))]),
                func("pair", vec![("p", udt("Pair"))]),
                func("set_status", vec![("s", udt("Status"))]),
                func("act", vec![("a", udt("Action"))]),
                func(
                    "big",
                    vec![("u", ScSpecTypeDef::U256), ("i", ScSpecTypeDef::I256)],
                ),
            ];
            entries
                .iter()
                .flat_map(|e| e.to_xdr(Limits::none()).unwrap())
                .collect()
        }

        /// Encode a call and pull out the ScVal arguments we built.
        fn args_of(function: &str, args: Value) -> Result<Vec<ScVal>, EncodeError> {
            let call = encode_call(&spec(), C, function, &args, None)?;
            let env = TransactionEnvelope::from_xdr_base64(&call.tx_xdr, Limits::none()).unwrap();
            let TransactionEnvelope::Tx(v1) = env else {
                panic!("expected v1 envelope")
            };
            let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
                panic!("expected invoke host function")
            };
            let HostFunction::InvokeContract(ic) = &op.host_function else {
                panic!("expected invoke contract")
            };
            Ok(ic.args.to_vec())
        }

        #[test]
        fn named_struct_becomes_a_key_sorted_map() {
            let args = args_of("submit", json!({"order": {"buyer": G, "amount": "500"}}))
                .expect("should encode");
            let ScVal::Map(Some(m)) = &args[0] else {
                panic!("expected a map, got {:?}", args[0])
            };
            // Sorted by symbol key: "amount" < "buyer", regardless of the order
            // the fields were declared or supplied in.
            let keys: Vec<String> = m
                .iter()
                .map(|e| match &e.key {
                    ScVal::Symbol(s) => s.to_utf8_string_lossy(),
                    other => panic!("expected symbol key, got {other:?}"),
                })
                .collect();
            assert_eq!(keys, vec!["amount", "buyer"]);
            assert!(matches!(m[0].val, ScVal::I128(_)));
            assert!(matches!(m[1].val, ScVal::Address(_)));
        }

        #[test]
        fn tuple_struct_becomes_a_positional_vec() {
            let args = args_of("pair", json!({"p": [1, 2]})).expect("should encode");
            let ScVal::Vec(Some(v)) = &args[0] else {
                panic!("expected a vec, got {:?}", args[0])
            };
            assert_eq!(v.to_vec(), vec![ScVal::U32(1), ScVal::U32(2)]);
        }

        #[test]
        fn struct_rejects_a_missing_field() {
            let err = args_of("submit", json!({"order": {"amount": "500"}})).unwrap_err();
            assert!(
                format!("{err}").contains("missing field \"buyer\""),
                "unhelpful error: {err}"
            );
        }

        #[test]
        fn enum_accepts_case_name_or_declared_value() {
            let by_name = args_of("set_status", json!({"s": "Filled"})).expect("by name");
            assert_eq!(by_name[0], ScVal::U32(7));
            let by_value = args_of("set_status", json!({"s": 7})).expect("by value");
            assert_eq!(by_value[0], ScVal::U32(7));
        }

        #[test]
        fn enum_rejects_undeclared_case_and_value() {
            let err = args_of("set_status", json!({"s": "Nope"})).unwrap_err();
            assert!(format!("{err}").contains("Active, Filled"), "got: {err}");
            // 3 is not a declared discriminant, even though it's a valid u32.
            let err = args_of("set_status", json!({"s": 3})).unwrap_err();
            assert!(
                format!("{err}").contains("not a declared value"),
                "got: {err}"
            );
        }

        #[test]
        fn union_void_case_is_a_bare_name() {
            let args = args_of("act", json!({"a": "Cancel"})).expect("should encode");
            let ScVal::Vec(Some(v)) = &args[0] else {
                panic!("expected a vec, got {:?}", args[0])
            };
            assert_eq!(v.len(), 1);
            assert!(matches!(&v[0], ScVal::Symbol(s) if s.to_utf8_string_lossy() == "Cancel"));
        }

        #[test]
        fn union_tuple_case_carries_its_values() {
            let args = args_of("act", json!({"a": {"Bid": [G, "250"]}})).expect("should encode");
            let ScVal::Vec(Some(v)) = &args[0] else {
                panic!("expected a vec, got {:?}", args[0])
            };
            assert_eq!(v.len(), 3);
            assert!(matches!(&v[0], ScVal::Symbol(s) if s.to_utf8_string_lossy() == "Bid"));
            assert!(matches!(v[1], ScVal::Address(_)));
            assert!(matches!(v[2], ScVal::I128(_)));
        }

        #[test]
        fn union_rejects_wrong_arity_and_shape() {
            let err = args_of("act", json!({"a": {"Bid": [G]}})).unwrap_err();
            assert!(
                format!("{err}").contains("expects 2 value(s), got 1"),
                "got: {err}"
            );
            // A tuple case can't be selected by bare name.
            let err = args_of("act", json!({"a": "Bid"})).unwrap_err();
            assert!(
                format!("{err}").contains("carries 2 value(s)"),
                "got: {err}"
            );
            let err = args_of("act", json!({"a": {"Cancel": [], "Bid": []}})).unwrap_err();
            assert!(format!("{err}").contains("exactly one case"), "got: {err}");
        }

        #[test]
        fn u256_and_i256_round_trip_through_limbs() {
            // 2^192 exercises every limb boundary: hi_hi=1, rest 0.
            let big = "6277101735386680763835789423207666416102355444464034512896";
            let args = args_of("big", json!({"u": big, "i": "-1"})).expect("should encode");
            assert_eq!(
                args[0],
                ScVal::U256(UInt256Parts {
                    hi_hi: 1,
                    hi_lo: 0,
                    lo_hi: 0,
                    lo_lo: 0
                })
            );
            // -1 is all ones in two's complement.
            assert_eq!(
                args[1],
                ScVal::I256(Int256Parts {
                    hi_hi: -1,
                    hi_lo: u64::MAX,
                    lo_hi: u64::MAX,
                    lo_lo: u64::MAX
                })
            );
        }

        #[test]
        fn i256_accepts_its_exact_bounds() {
            // i256::MIN = -2^255, whose magnitude is its own two's complement.
            let min =
                "-57896044618658097711785492504343953926634992332820282019728792003956564819968";
            let args = args_of("big", json!({"u": "0", "i": min})).expect("min should encode");
            assert_eq!(
                args[1],
                ScVal::I256(Int256Parts {
                    hi_hi: i64::MIN,
                    hi_lo: 0,
                    lo_hi: 0,
                    lo_lo: 0
                })
            );
            let max =
                "57896044618658097711785492504343953926634992332820282019728792003956564819967";
            let args = args_of("big", json!({"u": "0", "i": max})).expect("max should encode");
            assert_eq!(
                args[1],
                ScVal::I256(Int256Parts {
                    hi_hi: i64::MAX,
                    hi_lo: u64::MAX,
                    lo_hi: u64::MAX,
                    lo_lo: u64::MAX
                })
            );
        }

        #[test]
        fn out_of_range_256_bit_values_are_rejected() {
            // 2^256 — one past u256::MAX.
            let over =
                "115792089237316195423570985008687907853269984665640564039457584007913129639936";
            let err = args_of("big", json!({"u": over, "i": "0"})).unwrap_err();
            assert!(format!("{err}").contains("out of range"), "got: {err}");
            // 2^255 is one past i256::MAX (valid only as a negative).
            let over_signed =
                "57896044618658097711785492504343953926634992332820282019728792003956564819968";
            let err = args_of("big", json!({"u": "0", "i": over_signed})).unwrap_err();
            assert!(
                format!("{err}").contains("out of range for i256"),
                "got: {err}"
            );
            let err = args_of("big", json!({"u": "-1", "i": "0"})).unwrap_err();
            assert!(format!("{err}").contains("unsigned"), "got: {err}");
        }

        #[test]
        fn u256_max_is_accepted() {
            let max =
                "115792089237316195423570985008687907853269984665640564039457584007913129639935";
            let args = args_of("big", json!({"u": max, "i": "0"})).expect("should encode");
            assert_eq!(
                args[0],
                ScVal::U256(UInt256Parts {
                    hi_hi: u64::MAX,
                    hi_lo: u64::MAX,
                    lo_hi: u64::MAX,
                    lo_lo: u64::MAX
                })
            );
        }

        /// Test that unsupported types return precise error messages.
        fn unsupported_type_spec() -> Vec<u8> {
            use stellar_xdr::curr::ScSpecUdtUnionCaseVoidV0;
            // Specs with val, result, error, muxed_address args
            let entries = vec![
                ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                    doc: "".try_into().unwrap(),
                    name: "val_arg".try_into().unwrap(),
                    inputs: vec![ScSpecFunctionInputV0 {
                        doc: "".try_into().unwrap(),
                        name: "v".try_into().unwrap(),
                        type_: ScSpecTypeDef::Val,
                    }]
                    .try_into()
                    .unwrap(),
                    outputs: vec![].try_into().unwrap(),
                }),
                ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                    doc: "".try_into().unwrap(),
                    name: "result_arg".try_into().unwrap(),
                    inputs: vec![ScSpecFunctionInputV0 {
                        doc: "".try_into().unwrap(),
                        name: "r".try_into().unwrap(),
                        type_: ScSpecTypeDef::Result(Box::new(
                            stellar_xdr::curr::ScSpecUdtResultV0 {
                                ok_type: Box::new(ScSpecTypeDef::U32),
                                error_type: Box::new(ScSpecTypeDef::U32),
                            },
                        )),
                    }]
                    .try_into()
                    .unwrap(),
                    outputs: vec![].try_into().unwrap(),
                }),
                ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                    doc: "".try_into().unwrap(),
                    name: "error_arg".try_into().unwrap(),
                    inputs: vec![ScSpecFunctionInputV0 {
                        doc: "".try_into().unwrap(),
                        name: "e".try_into().unwrap(),
                        type_: ScSpecTypeDef::Error,
                    }]
                    .try_into()
                    .unwrap(),
                    outputs: vec![].try_into().unwrap(),
                }),
                ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                    doc: "".try_into().unwrap(),
                    name: "muxed_arg".try_into().unwrap(),
                    inputs: vec![ScSpecFunctionInputV0 {
                        doc: "".try_into().unwrap(),
                        name: "m".try_into().unwrap(),
                        type_: ScSpecTypeDef::MuxedAddress,
                    }]
                    .try_into()
                    .unwrap(),
                    outputs: vec![].try_into().unwrap(),
                }),
            ];
            entries
                .iter()
                .flat_map(|e| e.to_xdr(Limits::none()).unwrap())
                .collect()
        }

        fn unsupported_args_of(function: &str, args: Value) -> Result<Vec<ScVal>, EncodeError> {
            let call = encode_call(&unsupported_type_spec(), C, function, &args, None)?;
            let env = TransactionEnvelope::from_xdr_base64(&call.tx_xdr, Limits::none()).unwrap();
            let TransactionEnvelope::Tx(v1) = env else {
                panic!("expected v1 envelope")
            };
            let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
                panic!("expected invoke host function")
            };
            let HostFunction::InvokeContract(ic) = &op.host_function else {
                panic!("expected invoke contract")
            };
            Ok(ic.args.to_vec())
        }

        #[test]
        fn val_type_is_unsupported() {
            let err = unsupported_args_of("val_arg", json!({"v": null})).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("Val"), "error should mention Val type: {msg}");
            assert!(msg.contains("not yet supported"), "error should be clear: {msg}");
        }

        #[test]
        fn result_type_is_unsupported() {
            let err = unsupported_args_of("result_arg", json!({"r": null})).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("Result"), "error should mention Result type: {msg}");
            assert!(msg.contains("not yet supported"), "error should be clear: {msg}");
        }

        #[test]
        fn error_type_is_unsupported() {
            let err = unsupported_args_of("error_arg", json!({"e": null})).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("Error"), "error should mention Error type: {msg}");
            assert!(msg.contains("not yet supported"), "error should be clear: {msg}");
        }

        #[test]
        fn muxed_address_type_is_unsupported() {
            let err = unsupported_args_of("muxed_arg", json!({"m": null})).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("MuxedAddress"), "error should mention MuxedAddress type: {msg}");
            assert!(msg.contains("not yet supported"), "error should be clear: {msg}");
        }
    }
}
