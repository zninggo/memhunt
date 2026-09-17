use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn call_memhunt_scan(arguments: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_memhunt"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "memhunt_scan", "arguments": arguments}
    });
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all((request.to_string() + "\n").as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert!(response.get("error").is_none(), "response: {response}");
    child.wait().unwrap();
    response["result"].clone()
}

#[test]
fn mcp_tool_errors_use_is_error() {
    let missing = std::env::temp_dir()
        .join(format!("memhunt_mcp_missing_{}", std::process::id()))
        .with_extension("bin");
    let result = call_memhunt_scan(json!({
        "dump_path": missing,
        "ciphertext": "00112233445566778899aabbccddeeff"
    }));
    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains(missing.to_str().unwrap()),
        "error should contain dump path: {text}"
    );

    let dump = std::env::temp_dir()
        .join(format!("memhunt_mcp_dump_{}", std::process::id()))
        .with_extension("bin");
    std::fs::write(&dump, [0u8; 4096]).unwrap();
    let result = call_memhunt_scan(json!({
        "dump_path": dump,
        "ciphertext": "not-hex!!"
    }));
    assert_eq!(result["isError"], json!(true));
    let _ = std::fs::remove_file(dump);
}

#[test]
fn mcp_gcm_tag_hit() {
    use aes_gcm::aead::{AeadInPlace, KeyInit};

    let key: [u8; 16] = [0x81u8; 16];
    let nonce: [u8; 12] = [0x82u8; 12];
    let plaintext = br#"{"client":"mcp","gcm":true}"#;
    let key_offset = 2048;
    let fixt_dir = std::env::temp_dir().join(format!("memhunt_mcptest_{}", std::process::id()));
    std::fs::create_dir_all(&fixt_dir).unwrap();
    let dump_path = fixt_dir.join("dump.bin");
    let mut dump = vec![0x47u8; 4096];
    dump[key_offset..key_offset + 16].copy_from_slice(&key);
    std::fs::write(&dump_path, &dump).unwrap();

    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce.as_slice().into(), b"", &mut ciphertext)
        .unwrap();

    let result = call_memhunt_scan(json!({
        "dump_path": dump_path,
        "ciphertext": hex::encode(&ciphertext),
        "ciphers": "aes-128-gcm",
        "nonce": hex::encode(nonce),
        "tag": hex::encode(tag),
        "oracles": "json"
    }));
    assert_eq!(result["isError"], json!(false));
    let payload: Value =
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    let hit = &payload["hits"][0];
    assert_eq!(hit["mode"], json!("gcm"));
    assert_eq!(hit["key_offset"], json!(key_offset));
    assert_eq!(hit["nonce_hex"], json!(hex::encode(nonce)));
    assert_eq!(hit["matched_by"], json!("gcm-tag"));
    let _ = std::fs::remove_dir_all(fixt_dir);
}
