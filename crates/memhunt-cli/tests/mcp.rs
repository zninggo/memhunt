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
