//! MCP (Model Context Protocol) server mode: expose memhunt to AI agents.
//!
//! Implements the MCP stdio transport (JSON-RPC 2.0, newline-delimited) with
//! the minimal surface agents need: `initialize` handshake, `tools/list`, and
//! `tools/call` for `memhunt_scan` (ciphertext-driven key hunt),
//! `memhunt_key_schedules` (structure-only AES detection), and
//! `memhunt_hash_scan` (preimage / HMAC-key hunt). No async runtime, no SDK —
//! just stdio lines, so the binary stays a single static-ish executable.

use memhunt_core::hash_scan::{scan_hmac_keys, scan_preimages, HashAlgoSpec, HashScanConfig};
use memhunt_core::keysched::scan_key_schedules;
use memhunt_core::{scan, CipherChoice, Oracle, ScanConfig};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

pub const SERVER_NAME: &str = "memhunt";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &str = "2025-06-18";

fn tools_schema() -> Value {
    json!([
        {
            "name": "memhunt_scan",
            "description": "Hunt block-cipher keys in a memory dump given a known ciphertext. Slides a window over every dump offset, tries each window as a key (AES-128/192/256, DES, 3DES, SM4), and validates decryptions against oracles. CBC keys are verified IV-independently; the IV is located in a second pass.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the raw memory dump."},
                    "ciphertext": {"type": "string", "description": "Target ciphertext (hex or base64)."},
                    "ciphers": {"type": "string", "description": "Comma list: aes-128, aes-192, aes-256, des, 3des, sm4, aes (=all sizes), all. Default aes."},
                    "oracles": {"type": "string", "description": "Comma list: utf8, json, gzip, protobuf, known:<fragment>. Default utf8,json."},
                    "max_hits": {"type": "integer", "description": "Stop after N hits (0 = unlimited)."},
                    "iv": {"type": "string", "description": "Fixed IV (hex) for CBC; enables single-block ciphertext scans."},
                    "threads": {"type": "integer", "description": "Worker threads (default all cores)."}
                },
                "required": ["dump_path", "ciphertext"]
            }
        },
        {
            "name": "memhunt_key_schedules",
            "description": "Detect expanded AES key schedules in a memory dump with NO ciphertext required. Finds windows whose first words expand forward (FIPS-197 key schedule) to the words that follow them — e.g. an OpenSSL AES_KEY struct resident in memory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string"}
                },
                "required": ["dump_path"]
            }
        },
        {
            "name": "memhunt_hash_scan",
            "description": "Hunt hashes in a memory dump: (a) preimage search — find windows whose md5/sha1/sha256/sm3 digest equals a known target; (b) HMAC-key search — find windows that, as HMAC keys over a known message, produce a known MAC.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string"},
                    "mode": {"type": "string", "enum": ["preimage", "hmac_key"], "description": "preimage or hmac_key."},
                    "digest": {"type": "string", "description": "Target digest/MAC (hex)."},
                    "algos": {"type": "string", "description": "Comma list: md5, sha1, sha256, sm3. Default md5,sha1,sha256,sm3 (preimage) / required for hmac_key."},
                    "message": {"type": "string", "description": "Known message (utf8) for hmac_key mode."},
                    "min_len": {"type": "integer", "minimum": 1},
                    "max_len": {"type": "integer", "minimum": 1}
                },
                "required": ["dump_path", "mode", "digest"]
            }
        }
    ])
}

fn build_oracles(spec: &str) -> Result<Vec<Box<dyn Oracle>>, String> {
    memhunt_core::oracle::parse_spec(spec)
}

fn tool_scan(args: &Value) -> Result<Value, String> {
    let dump_path = args
        .get("dump_path")
        .and_then(Value::as_str)
        .ok_or("dump_path is required")?;
    let ciphertext_s = args
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or("ciphertext is required")?;
    let dump = std::fs::read(dump_path).map_err(|e| format!("read {dump_path}: {e}"))?;
    let ciphertext = decode_blob(ciphertext_s)?;

    let ciphers = match args.get("ciphers").and_then(Value::as_str) {
        Some(s) => CipherChoice::parse_list(s)?,
        None => CipherChoice::parse_list("aes")?,
    };
    let oracles = match args.get("oracles").and_then(Value::as_str) {
        Some(s) => build_oracles(s)?,
        None => build_oracles("utf8,json")?,
    };
    let max_hits = args.get("max_hits").and_then(Value::as_u64).unwrap_or(0) as usize;
    let fixed_iv = match args.get("iv").and_then(Value::as_str) {
        Some(h) => Some(hex::decode(h).map_err(|_| "invalid iv hex")?),
        None => None,
    };
    if let Some(n) = args.get("threads").and_then(Value::as_u64) {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(n as usize)
            .build_global();
    }

    let config = ScanConfig {
        ciphers,
        max_hits,
        scan_iv: true,
        fixed_iv,
    };
    let result = scan(&dump, &ciphertext, &oracles, &config)?;
    serde_json::to_value(&result).map_err(|e| e.to_string())
}

fn tool_key_schedules(args: &Value) -> Result<Value, String> {
    let dump_path = args
        .get("dump_path")
        .and_then(Value::as_str)
        .ok_or("dump_path is required")?;
    let dump = std::fs::read(dump_path).map_err(|e| format!("read {dump_path}: {e}"))?;
    let result = scan_key_schedules(&dump);
    serde_json::to_value(&result).map_err(|e| e.to_string())
}

fn tool_hash_scan(args: &Value) -> Result<Value, String> {
    let dump_path = args
        .get("dump_path")
        .and_then(Value::as_str)
        .ok_or("dump_path is required")?;
    let mode = args
        .get("mode")
        .and_then(Value::as_str)
        .ok_or("mode is required (preimage | hmac_key)")?;
    let digest_s = args
        .get("digest")
        .and_then(Value::as_str)
        .ok_or("digest is required")?;
    let digest = hex::decode(digest_s).map_err(|_| "digest must be hex")?;
    let dump = std::fs::read(dump_path).map_err(|e| format!("read {dump_path}: {e}"))?;

    let min_len = args.get("min_len").and_then(Value::as_u64).unwrap_or(8) as usize;
    let max_len = args.get("max_len").and_then(Value::as_u64).unwrap_or(128) as usize;
    if min_len < 1 || max_len < min_len {
        return Err("max_len must be >= min_len >= 1".into());
    }
    let config = HashScanConfig {
        lengths: memhunt_core::hash_scan::LengthRange {
            min: min_len,
            max: max_len,
        },
        max_hits: args.get("max_hits").and_then(Value::as_u64).unwrap_or(0) as usize,
    };

    match mode {
        "preimage" => {
            let algos = match args.get("algos").and_then(Value::as_str) {
                Some(s) => HashAlgoSpec::parse(s)?,
                None => vec![
                    HashAlgoSpec::Md5,
                    HashAlgoSpec::Sha1,
                    HashAlgoSpec::Sha256,
                    HashAlgoSpec::Sm3,
                ],
            };
            let result = scan_preimages(&dump, &digest, &algos, &config)?;
            serde_json::to_value(&result).map_err(|e| e.to_string())
        }
        "hmac_key" => {
            let algo_s = args
                .get("algos")
                .and_then(Value::as_str)
                .ok_or("algos is required for hmac_key mode (one of md5|sha1|sha256|sm3)")?;
            let algo = HashAlgoSpec::parse(algo_s)?;
            if algo.len() != 1 {
                return Err("hmac_key mode takes exactly one algo".into());
            }
            let message = args
                .get("message")
                .and_then(Value::as_str)
                .ok_or("message is required for hmac_key mode")?;
            let result = scan_hmac_keys(&algo[0], message.as_bytes(), &digest, &dump, &config)?;
            serde_json::to_value(&result).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown mode '{other}' (preimage | hmac_key)")),
    }
}

/// Decode hex or base64 ciphertext/digest input.
pub fn decode_blob(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.chars().all(|c| c.is_ascii_hexdigit()) && t.len().is_multiple_of(2) && !t.is_empty() {
        if let Ok(v) = hex::decode(t) {
            return Ok(v);
        }
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|_| "could not decode input as hex or base64".into())
}

fn dispatch(method: &str, params: &Value) -> Result<Value, String> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools_schema()})),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or("tools/call requires name")?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let result = match name {
                "memhunt_scan" => tool_scan(&args),
                "memhunt_key_schedules" => tool_key_schedules(&args),
                "memhunt_hash_scan" => tool_hash_scan(&args),
                other => return Err(format!("unknown tool '{other}'")),
            };
            match result {
                Ok(result) => Ok(json!({
                    "content": [{"type": "text", "text": result.to_string()}],
                    "isError": false
                })),
                Err(message) => Ok(json!({
                    "content": [{"type": "text", "text": message}],
                    "isError": true
                })),
            }
        }
        other => Err(format!("unknown method '{other}'")),
    }
}

/// Run the MCP stdio loop. Reads JSON-RPC requests line by line from stdin,
/// writes responses to stdout. Returns Ok(()) on clean EOF; errors only on
/// stdout write failures.
pub fn serve_stdio() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut line = String::new();
    let reader = std::io::BufReader::new(stdin.lock());
    let mut reader = reader;
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}
                });
                writeln!(out, "{}", resp)?;
                out.flush()?;
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        // Notifications (no id) get no response.
        if req.get("id").is_none() {
            continue;
        }
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let resp = match dispatch(method, &params) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(msg) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32602, "message": msg}
            }),
        };
        writeln!(out, "{}", resp)?;
        out.flush()?;
    }
    Ok(())
}
