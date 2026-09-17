use clap::Parser;
use memhunt_core::{scan, JsonOracle, KnownPlaintextOracle, Oracle, ScanConfig, Utf8Oracle};
use std::io::Write;
use std::process::ExitCode;

/// Hunt AES keys in a memory dump from a known ciphertext.
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

        /// Comma-separated oracles: utf8, json, known:<fragment>.
        #[arg(long, default_value = "utf8,json")]
        oracle: String,

        /// AES key sizes in bits: 128, 192, 256.
        #[arg(long, value_delimiter = ',', default_value = "128,192,256")]
        key_size: Vec<u32>,

        /// Stop after N hits (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_hits: usize,

        /// Fixed IV (hex) for CBC; enables single-block ciphertext scans.
        #[arg(long)]
        iv: Option<String>,

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
    if decoded.len() % 16 != 0 {
        return Err(format!(
            "ciphertext length {} is not a multiple of 16 (AES block size)",
            decoded.len()
        ));
    }
    Ok(decoded)
}

fn build_oracles(spec: &str) -> Result<Vec<Box<dyn Oracle>>, String> {
    let mut oracles: Vec<Box<dyn Oracle>> = Vec::new();
    for part in spec.split(',') {
        match part.trim() {
            "utf8" => oracles.push(Box::new(Utf8Oracle)),
            "json" => oracles.push(Box::new(JsonOracle)),
            spec if spec.starts_with("known:") => {
                oracles.push(Box::new(KnownPlaintextOracle {
                    fragment: spec.as_bytes()["known:".len()..].to_vec(),
                }));
            }
            "" => {}
            other => {
                return Err(format!(
                    "unknown oracle '{other}' (utf8 | json | known:<text>)"
                ))
            }
        }
    }
    if oracles.is_empty() {
        return Err("no oracle enabled".into());
    }
    Ok(oracles)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Scan {
        dump,
        target,
        encoding,
        oracle,
        key_size,
        max_hits,
        iv,
        no_iv_scan,
        json,
        threads,
    } = cli.command;

    let run = || -> Result<usize, String> {
        if let Some(n) = threads {
            rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build_global()
                .map_err(|e| e.to_string())?;
        }

        let ciphertext = decode_ciphertext(&target, &encoding)?;
        let oracles = build_oracles(&oracle)?;
        let fixed_iv = match &iv {
            Some(h) => Some(
                hex::decode(h)
                    .map_err(|_| "invalid --iv hex")?
                    .try_into()
                    .map_err(|_: Vec<u8>| "--iv must be exactly 16 bytes of hex")?,
            ),
            None => None,
        };
        let key_sizes = key_size
            .iter()
            .map(|b| Ok((b / 8) as usize))
            .collect::<Result<Vec<usize>, String>>()?;
        let config = ScanConfig {
            key_sizes,
            max_hits,
            scan_iv: !no_iv_scan,
            fixed_iv,
        };

        let dump_bytes = std::fs::read(&dump).map_err(|e| format!("read {dump}: {e}"))?;
        eprintln!(
            "memhunt: dump={} ({:.1} MiB), ciphertext={} bytes, oracles=[{}], key sizes={:?}",
            dump,
            dump_bytes.len() as f64 / (1024.0 * 1024.0),
            ciphertext.len(),
            oracle,
            config.key_sizes
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
        Ok(0) => ExitCode::from(1),
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("memhunt: error: {e}");
            ExitCode::from(2)
        }
    }
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
