use anyhow::{bail, ensure, Context, Result};
use cpio::{NewcBuilder, NewcReader};
use flate2::read::GzDecoder;
use std::io::{Cursor, Read, Write};

/// One cpio entry with the metadata the kernel restores when it unpacks the
/// archive into rootfs.
#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub nlink: u32,
    pub dev: (u32, u32),
    pub rdev: (u32, u32),
    pub data: Vec<u8>,
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// The permissions a stock ramdisk gives its links, such as the commands
/// in system/bin that stand for toybox.
const LINK_MODE: u32 = 0o755;

/// LZ4's legacy framing, the one the kernel's initramfs unpacker reads: a
/// magic, then blocks of at most eight megabytes, each of those preceded by
/// its compressed size.
const LZ4_MAGIC: u32 = 0x184C_2102;
const LZ4_BLOCK: usize = 8 * 1024 * 1024;

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// An initramfs held in memory, so entries keep their owners, modes and
/// device numbers exactly as the archive had them.
pub struct Ramdisk {
    pub entries: Vec<Entry>,
}

impl Ramdisk {
    /// Unpack a newc archive compressed either with gzip, as version 0 to 2
    /// boot images carry it, or with LZ4 in the legacy framing the kernel
    /// reads.
    pub fn decode(compressed: &[u8]) -> Result<Self> {
        let cpio = if compressed.starts_with(&[0x1f, 0x8b]) {
            let mut out = Vec::new();
            GzDecoder::new(compressed).read_to_end(&mut out).context("gzip decode")?;
            out
        } else {
            lz4_legacy_decode(compressed)?
        };
        let mut entries = Vec::new();
        let mut rest = Cursor::new(cpio.as_slice());
        loop {
            let mut r = NewcReader::new(rest).context("cpio entry")?;
            if r.entry().is_trailer() {
                break;
            }
            let e = r.entry();
            let mut entry = Entry {
                name: e.name().to_string(),
                mode: e.mode(),
                uid: e.uid(),
                gid: e.gid(),
                mtime: e.mtime(),
                nlink: e.nlink(),
                dev: (e.dev_major(), e.dev_minor()),
                rdev: (e.rdev_major(), e.rdev_minor()),
                data: Vec::with_capacity(e.file_size() as usize),
            };
            r.read_to_end(&mut entry.data).with_context(|| format!("cpio data of {}", entry.name))?;
            entries.push(entry);
            rest = r.finish().context("cpio entry end")?;
        }
        Ok(Ramdisk { entries })
    }

    /// Pack as a newc archive compressed the way AOSP packs boot ramdisks,
    /// with LZ4 in the legacy framing (the kernel's initramfs unpacker reads
    /// no other LZ4 framing).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut cpio = Vec::new();
        for (ino, e) in self.entries.iter().enumerate() {
            let size = u32::try_from(e.data.len()).with_context(|| format!("{} is too large", e.name))?;
            let mut w = NewcBuilder::new(&e.name)
                .ino(300_000 + ino as u32)
                .mode(e.mode)
                .uid(e.uid)
                .gid(e.gid)
                .mtime(e.mtime)
                .nlink(e.nlink)
                .dev_major(e.dev.0)
                .dev_minor(e.dev.1)
                .rdev_major(e.rdev.0)
                .rdev_minor(e.rdev.1)
                .write(&mut cpio, size);
            w.write_all(&e.data)?;
            w.finish()?;
        }
        cpio::newc::trailer(&mut cpio)?;
        Ok(lz4_legacy(&cpio))
    }

    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Replace a regular file's contents, keeping its owner and mode.
    pub fn replace(&mut self, name: &str, data: Vec<u8>) -> Result<()> {
        match self.entries.iter_mut().find(|e| e.name == name) {
            Some(e) if e.mode & S_IFMT == S_IFREG => {
                e.data = data;
                Ok(())
            }
            Some(_) => bail!("{name} is not a regular file"),
            None => bail!("{name} is not in the ramdisk"),
        }
    }

    /// Add a root-owned regular file, creating missing parent directories.
    pub fn add(&mut self, name: &str, mode: u32, data: Vec<u8>) -> Result<()> {
        self.insert(name, S_IFREG | mode, data)
    }

    /// Point `name` to `target`: a link already there is pointed anew, and
    /// otherwise a root-owned link is added, creating missing parent
    /// directories.
    pub fn link(&mut self, name: &str, target: &str) -> Result<()> {
        match self.entries.iter_mut().find(|e| e.name == name) {
            Some(e) if e.mode & S_IFMT == S_IFLNK => {
                e.data = target.as_bytes().to_vec();
                Ok(())
            }
            Some(_) => bail!("{name} is in the ramdisk and is not a link"),
            None => self.insert(name, S_IFLNK | LINK_MODE, target.as_bytes().to_vec()),
        }
    }

    fn insert(&mut self, name: &str, mode: u32, data: Vec<u8>) -> Result<()> {
        if self.find(name).is_some() {
            bail!("{name} is already in the ramdisk");
        }
        let parts: Vec<&str> = name.split('/').collect();
        let mut parent = String::new();
        for part in &parts[..parts.len() - 1] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(part);
            match self.find(&parent) {
                Some(e) if e.is_dir() => {}
                Some(_) => bail!("{parent} is not a directory"),
                None => self.entries.push(root_entry(&parent, S_IFDIR | 0o755, Vec::new())),
            }
        }
        self.entries.push(root_entry(name, mode, data));
        Ok(())
    }
}

fn root_entry(name: &str, mode: u32, data: Vec<u8>) -> Entry {
    let nlink = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
    Entry { name: name.to_string(), mode, uid: 0, gid: 0, mtime: 0, nlink, dev: (0, 0), rdev: (0, 0), data }
}

/// Unpack LZ4's legacy framing: a magic, then each block's compressed size
/// followed by that block, the last block short.
fn lz4_legacy_decode(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(data.len() >= 4, "the ramdisk is shorter than its compression magic");
    let magic = u32::from_le_bytes(data[..4].try_into().expect("four bytes"));
    ensure!(magic == LZ4_MAGIC, "the ramdisk is compressed neither with gzip nor with LZ4 ({magic:#x})");
    let mut at = 4;
    let mut out = Vec::new();
    while at < data.len() {
        ensure!(at + 4 <= data.len(), "a compressed size runs past the end of the ramdisk");
        let len = u32::from_le_bytes(data[at..at + 4].try_into().expect("four bytes")) as usize;
        at += 4;
        ensure!(at + len <= data.len(), "a compressed block runs past the end of the ramdisk");
        let start = out.len();
        out.resize(start + LZ4_BLOCK, 0);
        let written = lz4_flex::block::decompress_into(&data[at..at + len], &mut out[start..]).context("lz4 block")?;
        out.truncate(start + written);
        at += len;
    }
    Ok(out)
}

fn lz4_legacy(input: &[u8]) -> Vec<u8> {
    let mut out = LZ4_MAGIC.to_le_bytes().to_vec();
    for block in input.chunks(LZ4_BLOCK) {
        let compressed = lz4_flex::block::compress(block);
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&compressed);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_metadata() {
        let mut rd = Ramdisk { entries: Vec::new() };
        rd.add("system/bin/recovery", 0o750, b"binary".to_vec()).unwrap();
        rd.entries.push(Entry {
            name: "dev/console".into(),
            mode: 0o020600,
            uid: 0,
            gid: 0,
            mtime: 0,
            nlink: 1,
            dev: (0, 0),
            rdev: (5, 1),
            data: Vec::new(),
        });
        let back = Ramdisk::decode(&rd.encode().unwrap()).unwrap();
        let names: Vec<&str> = back.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["system", "system/bin", "system/bin/recovery", "dev/console"]);
        let bin = back.find("system/bin/recovery").unwrap();
        assert_eq!((bin.mode, bin.data.as_slice()), (S_IFREG | 0o750, b"binary".as_slice()));
        assert_eq!(back.find("dev/console").unwrap().rdev, (5, 1));
        assert!(rd.add("system/bin/recovery", 0o644, Vec::new()).is_err());
    }

    #[test]
    fn a_link_is_kept_as_a_link_to_its_target() {
        let mut rd = Ramdisk { entries: Vec::new() };
        rd.add("system/bin/recovery", 0o750, b"binary".to_vec()).unwrap();
        rd.link("system/bin/zstd", "recovery").unwrap();
        rd.link("sbin/sh", "/system/bin/sh").unwrap();
        let back = Ramdisk::decode(&rd.encode().unwrap()).unwrap();
        let zstd = back.find("system/bin/zstd").unwrap();
        assert_eq!((zstd.mode, zstd.data.as_slice()), (S_IFLNK | LINK_MODE, b"recovery".as_slice()));
        assert_eq!((zstd.uid, zstd.gid, zstd.nlink), (0, 0, 1));
        assert!(back.find("sbin").is_some_and(Entry::is_dir), "a missing folder is made");
        assert!(rd.link("system/bin/recovery", "zstd").is_err(), "a file is no link to point anew");
        assert!(rd.link("system/bin/recovery/7za", "recovery").is_err(), "a file holds no links");
    }

    #[test]
    fn a_link_already_there_is_pointed_anew_keeping_the_rest_of_its_entry() {
        let mut rd = Ramdisk { entries: Vec::new() };
        rd.add("system/bin/ziptool", 0o755, b"binary".to_vec()).unwrap();
        rd.entries.push(Entry {
            name: "system/bin/unzip".into(),
            mode: S_IFLNK | 0o755,
            uid: 0,
            gid: 2000,
            mtime: 0,
            nlink: 1,
            dev: (0, 0),
            rdev: (0, 0),
            data: b"ziptool".to_vec(),
        });
        let count = rd.entries.len();
        rd.link("system/bin/unzip", "recovery").unwrap();
        let back = Ramdisk::decode(&rd.encode().unwrap()).unwrap();
        let unzip = back.find("system/bin/unzip").unwrap();
        assert_eq!((unzip.data.as_slice(), unzip.mode, unzip.gid), (b"recovery".as_slice(), S_IFLNK | 0o755, 2000));
        assert_eq!(back.entries.len(), count, "no second entry of the name");
        assert!(back.find("system/bin/ziptool").is_some(), "what it pointed to stays");
    }

    #[test]
    fn gzip_ramdisks_are_unpacked_too() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut rd = Ramdisk { entries: Vec::new() };
        rd.add("system/bin/recovery", 0o750, b"binary".to_vec()).unwrap();
        let cpio = {
            let mut cpio = Vec::new();
            for (ino, e) in rd.entries.iter().enumerate() {
                let mut w = NewcBuilder::new(&e.name)
                    .ino(300_000 + ino as u32)
                    .mode(e.mode)
                    .uid(e.uid)
                    .gid(e.gid)
                    .mtime(e.mtime)
                    .nlink(e.nlink)
                    .dev_major(0)
                    .dev_minor(0)
                    .rdev_major(0)
                    .rdev_minor(0)
                    .write(&mut cpio, e.data.len() as u32);
                w.write_all(&e.data).unwrap();
                w.finish().unwrap();
            }
            cpio::newc::trailer(&mut cpio).unwrap();
            cpio
        };
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&cpio).unwrap();
        let compressed = gz.finish().unwrap();
        let back = Ramdisk::decode(&compressed).unwrap();
        assert_eq!(back.find("system/bin/recovery").unwrap().data, b"binary".as_slice());
    }
}
