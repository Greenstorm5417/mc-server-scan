//! On-disk scan cursor so Ctrl-C / a crash can resume the same shuffle.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub seed: u64,
    pub index: u64,
    pub total: u64,
    pub fingerprint: u64,
}

pub fn load(path: &Path) -> Result<Option<Checkpoint>> {
    if !path.exists() {
        return Ok(None);
    }
    let text =
        fs::read_to_string(path).with_context(|| format!("reading state {}", path.display()))?;
    parse(&text).map(Some)
}

pub fn save(path: &Path, ckpt: &Checkpoint) -> Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        fs::create_dir_all(dir).ok();
    }
    let body = format!(
        "v=1\nseed={}\nindex={}\ntotal={}\nfp={:016x}\n",
        ckpt.seed, ckpt.index, ckpt.total, ckpt.fingerprint
    );
    let tmp = tmp_path(path);
    fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

pub fn clear(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(tmp_path(path));
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn parse(text: &str) -> Result<Checkpoint> {
    let mut seed = None;
    let mut index = None;
    let mut total = None;
    let mut fingerprint = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "seed" => seed = Some(v.parse()?),
            "index" => index = Some(v.parse()?),
            "total" => total = Some(v.parse()?),
            "fp" => fingerprint = Some(u64::from_str_radix(v.trim(), 16)?),
            _ => {}
        }
    }
    let (Some(seed), Some(index), Some(total), Some(fingerprint)) =
        (seed, index, total, fingerprint)
    else {
        bail!("incomplete state file");
    };
    Ok(Checkpoint {
        seed,
        index,
        total,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("mc-scan-state-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let ckpt = Checkpoint {
            seed: 42,
            index: 1000,
            total: 5000,
            fingerprint: 0xDEAD_BEEF_CAFE_BABE,
        };
        let path = dir.join("mc-scan.state");
        save(&path, &ckpt).unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded, ckpt);
        clear(&path);
        assert!(load(&path).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
