mod mcp;

use clap::Parser;
use memhunt_core::{
    scan, CipherChoice, HashAlgoSpec, HashScanConfig, LengthRange, Oracle, ScanConfig,
};
use std::io::Write;
use std::process::ExitCode;

/// Hunt keys, key schedules, and hash preimages in memory dumps.
#[derive(Debug, Parser)]
#[command(name = "memhunt", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Scan a dump for keys that decrypt the target ciphertext.
    Scan {
        /// Path to the memory dump (raw binary).
        dump: String,

        /// Target ciphertext (hex or base64, auto-detected unless --encoding is set).
        #[arg(short, long)]
        target: String,

        /// Force ciphertext encoding: hex | base64 | utf8.
        #[arg(long, default_value = "auto")]
        encoding: String,

        /// Comma-separated oracles: utf8, utf16le, json, gzip, protobuf, known:<fragment>.
        #[arg(long, default_value = "utf8,json")]
        oracle: String,

        /// Cipher families to try: aes-128, aes-192, aes-256, des, 3des, sm4,
        /// aes (= all sizes), all, or AES with -ctr/-gcm suffix.
        #[arg(long, value_delimiter = ',', default_value = "aes")]
        cipher: String,

        /// Stop after N hits (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_hits: usize,

        /// Fixed IV (hex) for CBC; enables single-block ciphertext scans.
        #[arg(long)]
        iv: Option<String>,

        /// CTR initial counter block or GCM nonce (hex).
        #[arg(long)]
        nonce: Option<String>,

        /// GCM authentication tag (hex).
        #[arg(long)]
        tag: Option<String>,

        /// GCM additional authenticated data (hex).
        #[arg(long)]
        aad: Option<String>,

        /// Disable the IV scan pass after a CBC hit.
        #[arg(long)]
        no_iv_scan: bool,

        /// Output JSON Lines to stdout (default: human-readable).
        #[arg(long)]
        json: bool,

        /// Worker threads (default: all cores).
        #[arg(long)]
        threads: Option<usize>,
    },

    /// Detect expanded AES key schedules in a dump (no ciphertext needed).
    KeySchedules {
        /// Path to the memory dump (raw binary).
        dump: String,

        /// Output JSON Lines to stdout (default: human-readable).
        #[arg(long)]
        json: bool,
    },

    /// Hunt hashes: preimage search or HMAC-key search.
    Hash {
        /// Path to the memory dump (raw binary).
        dump: String,

        /// Search mode: preimage (find the hashed data) or hmac_key (find the
        /// secret that HMACs a known message to the target).
        #[arg(long)]
        mode: String,

        /// Target digest / MAC (hex).
        #[arg(long)]
        digest: String,

        /// Comma-separated hash algos: md5, sha1, sha256, sm3.
        #[arg(long, value_delimiter = ',', default_value = "md5,sha1,sha256,sm3")]
        algos: String,

        /// Known message (utf8) for hmac_key mode.
        #[arg(long)]
        message: Option<String>,

        /// Minimum window length for preimage/hmac-key search.
        #[arg(long, default_value = "8")]
        min_len: usize,

        /// Maximum window length for preimage/hmac-key search.
        #[arg(long, default_value = "128")]
        max_len: usize,

        /// Output JSON Lines to stdout (default: human-readable).
        #[arg(long)]
        json: bool,
    },

    /// Run as an MCP server on stdio (for AI agents).
    Serve,
}

fn decode_ciphertext(target: &str, encoding: &str) -> Result<Vec<u8>, String> {
    let try_hex = |s: &str| {
        let t = s.trim();
        if t.len().is_multiple_of(2) && !t.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(t).ok()
        } else {
            None
        }
    };
    let try_b64 = |s: &str| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .ok()
    };

    let decoded = match encoding {
        "hex" => try_hex(target).ok_or("target is not valid hex")?,
        "base64" => try_b64(target).ok_or("target is not valid base64")?,
        "utf8" => target.as_bytes().to_vec(),
        "auto" => try_hex(target)
            .or_else(|| try_b64(target))
            .ok_or("could not auto-detect target as hex or base64; use --encoding")?,
        other => return Err(format!("unknown encoding '{other}'")),
    };
    if decoded.is_empty() {
        return Err("ciphertext is empty".into());
    }
    Ok(decoded)
}

fn print_human(out: &mut impl Write, hit: &memhunt_core::Hit) {
    let _ = writeln!(
        out,
        "[{}] {} {} key=@{} {}",
        format!("{:?}", hit.confidence).to_lowercase(),
        hit.algo,
        format!("{:?}", hit.mode).to_lowercase(),
        hit.key_offset,
        hit.key_hex
    );
    if let Some(iv) = &hit.iv_hex {
        let off = hit
            .iv_offset
            .map(|o| format!("@{o}"))
            .unwrap_or_else(|| "fixed".into());
        let _ = writeln!(out, "       iv ={} {}", off, iv);
    }
    if let Some(nonce) = &hit.nonce_hex {
        let _ = writeln!(out, "       nonce ={nonce}");
    }
    for (i, c) in hit.iv_candidates.iter().enumerate() {
        let preview = c
            .block0_utf8
            .as_deref()
            .map(|s| s.chars().take(40).collect::<String>())
            .unwrap_or_else(|| "(non-utf8)".to_string());
        let _ = writeln!(
            out,
            "       iv-candidate[{}] @{} {:?} matched_by={} block0={preview}",
            i, c.iv_offset, c.confidence, c.matched_by,
        );
    }
    if let Some(pad) = &hit.padding {
        let _ = writeln!(out, "       padding: {pad}");
    }
    match &hit.plaintext_utf8 {
        Some(s) => {
            let preview: String = s.chars().take(120).collect();
            let _ = writeln!(out, "       plaintext: {preview}");
        }
        None => {
            let preview: String = hit.plaintext_hex.chars().take(96).collect();
            let _ = writeln!(out, "       plaintext(hex): {preview}");
        }
    }
    let _ = writeln!(out);
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Scan {
            dump,
            target,
            encoding,
            oracle,
            cipher,
            max_hits,
            iv,
            nonce,
            tag,
            aad,
            no_iv_scan,
            json,
            threads,
        } => run_scan(
            &dump,
            &target,
            &encoding,
            &oracle,
            &cipher,
            max_hits,
            iv,
            nonce,
            tag,
            aad,
            !no_iv_scan,
            json,
            threads,
        ),
        Command::KeySchedules { dump, json } => run_key_schedules(&dump, json),
        Command::Hash {
            dump,
            mode,
            digest,
            algos,
            message,
            min_len,
            max_len,
            json,
        } => run_hash(
            &dump, &mode, &digest, &algos, message, min_len, max_len, json,
        ),
        Command::Serve => match mcp::serve_stdio() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("memhunt: mcp server error: {e}");
                2
            }
        },
    };
    ExitCode::from(code)
}

#[allow(clippy::too_many_arguments)]
fn run_scan(
    dump_path: &str,
    target: &str,
    encoding: &str,
    oracle: &str,
    cipher_spec: &str,
    max_hits: usize,
    iv: Option<String>,
    nonce: Option<String>,
    tag: Option<String>,
    aad: Option<String>,
    scan_iv: bool,
    json: bool,
    threads: Option<usize>,
) -> u8 {
    let run = || -> Result<usize, String> {
        if let Some(n) = threads {
            rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build_global()
                .map_err(|e| e.to_string())?;
        }

        let ciphertext = decode_ciphertext(target, encoding)?;
        let oracles: Vec<Box<dyn Oracle>> = memhunt_core::oracle::parse_spec(oracle)?;
        let selection = CipherChoice::parse_list(cipher_spec)?;
        let decode_hex_arg = |value: &Option<String>, name: &str| {
            value
                .as_deref()
                .map(hex::decode)
                .transpose()
                .map_err(|_| format!("invalid --{name} hex"))
        };
        let fixed_iv = decode_hex_arg(&iv, "iv")?;
        let nonce = decode_hex_arg(&nonce, "nonce")?;
        let tag = decode_hex_arg(&tag, "tag")?;
        let aad = decode_hex_arg(&aad, "aad")?;
        let config = ScanConfig {
            ciphers: selection.ciphers,
            mode: selection.mode,
            max_hits,
            scan_iv,
            fixed_iv,
            nonce,
            tag,
            aad,
        };

        let dump_bytes = std::fs::read(dump_path).map_err(|e| format!("read {dump_path}: {e}"))?;
        eprintln!(
            "memhunt: dump={} ({:.1} MiB), ciphertext={} bytes, oracles=[{}], ciphers={}, mode={:?}",
            dump_path,
            dump_bytes.len() as f64 / (1024.0 * 1024.0),
            ciphertext.len(),
            oracle,
            cipher_spec,
            config.mode
        );

        let result = scan(&dump_bytes, &ciphertext, &oracles, &config)?;
        eprintln!(
            "memhunt: {} candidates in {} ms ({}/s)",
            result.stats.candidates_tried,
            result.stats.duration_ms,
            result.stats.candidates_per_sec
        );

        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for hit in &result.hits {
            if json {
                serde_json::to_writer(&mut out, hit).map_err(|e| e.to_string())?;
                writeln!(out).map_err(|e| e.to_string())?;
            } else {
                print_human(&mut out, hit);
            }
        }
        if result.hits.is_empty() {
            eprintln!("memhunt: no hits");
        }
        Ok(result.hits.len())
    };

    match run() {
        Ok(0) => 1,
        Ok(_) => 0,
        Err(e) => {
            eprintln!("memhunt: error: {e}");
            2
        }
    }
}

fn run_key_schedules(dump_path: &str, json: bool) -> u8 {
    let run = || -> Result<usize, String> {
        let dump_bytes = std::fs::read(dump_path).map_err(|e| format!("read {dump_path}: {e}"))?;
        eprintln!(
            "memhunt: dump={} ({:.1} MiB), mode=key-schedules",
            dump_path,
            dump_bytes.len() as f64 / (1024.0 * 1024.0)
        );
        let result = memhunt_core::scan_key_schedules(&dump_bytes);
        eprintln!(
            "memhunt: {} candidates in {} ms ({}/s)",
            result.stats.candidates_tried,
            result.stats.duration_ms,
            result.stats.candidates_per_sec
        );
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for hit in &result.hits {
            if json {
                serde_json::to_writer(&mut out, hit).map_err(|e| e.to_string())?;
                writeln!(out).map_err(|e| e.to_string())?;
            } else {
                let _ = writeln!(
                    out,
                    "[high] {} key-schedule @{} key={}",
                    hit.algo, hit.offset, hit.key_hex
                );
                let _ = writeln!(out, "       words_validated: {}", hit.words_validated);
                let _ = writeln!(out);
            }
        }
        if result.hits.is_empty() {
            eprintln!("memhunt: no hits");
        }
        Ok(result.hits.len())
    };
    match run() {
        Ok(0) => 1,
        Ok(_) => 0,
        Err(e) => {
            eprintln!("memhunt: error: {e}");
            2
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_hash(
    dump_path: &str,
    mode: &str,
    digest: &str,
    algos: &str,
    message: Option<String>,
    min_len: usize,
    max_len: usize,
    json: bool,
) -> u8 {
    let run = || -> Result<usize, String> {
        let digest_bytes = hex::decode(digest).map_err(|_| "digest must be hex")?;
        let dump_bytes = std::fs::read(dump_path).map_err(|e| format!("read {dump_path}: {e}"))?;
        let config = HashScanConfig {
            lengths: LengthRange {
                min: min_len,
                max: max_len,
            },
            max_hits: 0,
        };

        match mode {
            "preimage" => {
                let algos = HashAlgoSpec::parse(algos)?;
                eprintln!(
                    "memhunt: dump={} ({:.1} MiB), mode=preimage, algos=[{}], lens {}..={}",
                    dump_path,
                    dump_bytes.len() as f64 / (1024.0 * 1024.0),
                    algos
                        .iter()
                        .map(|a| a.label())
                        .collect::<Vec<_>>()
                        .join(","),
                    min_len,
                    max_len
                );
                let result =
                    memhunt_core::scan_preimages(&dump_bytes, &digest_bytes, &algos, &config)?;
                emit_hash_result(&result, json)?;
                Ok(result.hits.len())
            }
            "hmac_key" => {
                let algo_list = HashAlgoSpec::parse(algos)?;
                let algo = algo_list.first().ok_or("no hash algo specified")?;
                let msg = message.ok_or("--message is required for hmac_key mode")?;
                eprintln!(
                    "memhunt: dump={} ({:.1} MiB), mode=hmac_key, algo={}, lens {}..={}",
                    dump_path,
                    dump_bytes.len() as f64 / (1024.0 * 1024.0),
                    algo.label(),
                    min_len,
                    max_len
                );
                let result = memhunt_core::scan_hmac_keys(
                    algo,
                    msg.as_bytes(),
                    &digest_bytes,
                    &dump_bytes,
                    &config,
                )?;
                emit_hash_result(&result, json)?;
                Ok(result.hits.len())
            }
            other => Err(format!("unknown mode '{other}' (preimage | hmac_key)")),
        }
    };
    match run() {
        Ok(0) => 1,
        Ok(_) => 0,
        Err(e) => {
            eprintln!("memhunt: error: {e}");
            2
        }
    }
}

fn emit_hash_result(result: &memhunt_core::HashScanResult, json: bool) -> Result<(), String> {
    eprintln!(
        "memhunt: {} candidates in {} ms ({}/s)",
        result.stats.candidates_tried, result.stats.duration_ms, result.stats.candidates_per_sec
    );
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for hit in &result.hits {
        if json {
            serde_json::to_writer(&mut out, hit).map_err(|e| e.to_string())?;
            writeln!(out).map_err(|e| e.to_string())?;
        } else {
            let preview: String =
                String::from_utf8_lossy(&hex::decode(&hit.match_hex).unwrap_or_default())
                    .chars()
                    .take(80)
                    .collect();
            let _ = writeln!(
                out,
                "[high] {} {} @{} len={} {}",
                hit.algo, hit.kind, hit.offset, hit.length, hit.match_hex
            );
            let _ = writeln!(out, "       data: {preview}");
            let _ = writeln!(out);
        }
    }
    if result.hits.is_empty() {
        eprintln!("memhunt: no hits");
    }
    Ok(())
}
