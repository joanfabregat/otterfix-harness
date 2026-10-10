use otterfix::{policy::Policy, trivy, Error, Result};
use std::fs::File;
use std::io::{Read, Write};

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
fn read_bounded(path: &str) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|error| Error(format!("cannot open input: {error}")))?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error(format!("cannot read input: {error}")))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Error("input exceeds 16 MiB limit".into()));
    }
    Ok(bytes)
}
fn execute() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("Usage: otterfix triage --report PATH --policy PATH\n\nReads Trivy schema v2 JSON and trusted schema v1 policy; emits triage JSON.\nNo model calls, repository execution, patching, or validation are performed.");
        return Ok(());
    }
    if args.len() != 5 || args[0] != "triage" || args[1] != "--report" || args[3] != "--policy" {
        return Err(Error(
            "usage: otterfix triage --report PATH --policy PATH".into(),
        ));
    }
    let batch = trivy::ingest(&read_bounded(&args[2])?)?;
    let policy: Policy = serde_json::from_slice(&read_bounded(&args[4])?)?;
    let result = policy.triage(batch)?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &result)?;
    writeln!(output).map_err(|error| Error(format!("cannot write JSON: {error}")))?;
    Ok(())
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("otterfix: {error}");
        std::process::exit(2);
    }
}
