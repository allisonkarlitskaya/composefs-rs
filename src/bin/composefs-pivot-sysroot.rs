use std::io::Read;
use std::path::Path;

use anyhow::{bail, Result};

use composefs_experiments::{fsverity::Sha256HashValue, repository::Repository};

fn parse_composefs_cmdline() -> Result<Sha256HashValue> {
    let mut cmdline = vec![];
    let mut proc_cmdline = std::fs::File::open("/proc/cmdline")?;
    proc_cmdline.read_to_end(&mut cmdline)?;
    // TODO?: officially we need to understand quoting with double-quotes...
    for part in cmdline.split(|c| *c == b' ') {
        if let Some(digest) = part.strip_prefix(b"composefs=") {
            let mut value = [0; 32];
            hex::decode_to_slice(digest, &mut value)?;
            return Ok(value);
        }
    }
    bail!("Unable to find composefs= cmdline parameter");
}

fn main() -> Result<()> {
    let repo = Repository::open_system()?;
    let image = parse_composefs_cmdline()?;
    repo.pivot_sysroot(&hex::encode(image), Path::new("/sysroot"))?;

    Ok(())
}
