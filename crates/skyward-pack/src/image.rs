use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0, HeaderV0Versioned, HeaderV3};
use anyhow::{anyhow, ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const PAGE: usize = 4096;

/// A boot image split into its header and the sections after it. Versions 0
/// to 2, which phones that keep a recovery partition use, also hold a second
/// stage bootloader, a recovery DTBO and a DTB; versions 3 and 4 hold only a
/// kernel and a ramdisk.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    pub second: Vec<u8>,
    pub recovery_dtbo: Vec<u8>,
    pub dtb: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

/// The digest a version 0 to 2 header carries over the sections after it:
/// each section's contents, then its size, a section of no size having no
/// contents.
fn sections_digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update((part.len() as u32).to_le_bytes());
    }
    hasher.finalize().into()
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let header = Header::parse(&mut Cursor::new(&bytes)).with_context(|| format!("{}: header", path.display()))?;
        match header {
            Header::V3(h) => {
                let kernel = section(&bytes, HeaderV3::kernel_position(), h.kernel_size, "kernel")?;
                let ramdisk = section(&bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?;
                Ok(BootImage { header: Header::V3(h), kernel, ramdisk, second: Vec::new(), recovery_dtbo: Vec::new(), dtb: Vec::new() })
            }
            Header::V0(h) => {
                let kernel = section(&bytes, h.kernel_position(), h.kernel_size, "kernel")?;
                let ramdisk = section(&bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?;
                let second = section(&bytes, h.second_bootloader_position(), h.second_bootloader_size, "second stage bootloader")?;
                let (recovery_dtbo, dtb) = match h.versioned {
                    HeaderV0Versioned::V0 => (Vec::new(), Vec::new()),
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => {
                        (section(&bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?, Vec::new())
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => {
                        let dtb = h.dtb_position().with_context(|| format!("{}: a version 2 header has a DTB", path.display()))?;
                        (
                            section(&bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?,
                            section(&bytes, dtb, dtb_size, "DTB")?,
                        )
                    }
                };
                Ok(BootImage { header: Header::V0(h), kernel, ramdisk, second, recovery_dtbo, dtb })
            }
        }
    }

    /// The image with sizes taken from its parts. A version 4 header keeps its
    /// version but carries no boot signature; unlocked bootloaders do not ask
    /// for one.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match &self.header {
            Header::V3(h) => {
                let mut header = h.clone();
                header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                header.v4_signature_size = header.v4_signature_size.map(|_| 0);
                let mut out = Vec::new();
                Header::V3(header).write(&mut out).context("write header")?;
                pad(&mut out, PAGE);
                out.extend_from_slice(&self.kernel);
                pad(&mut out, PAGE);
                out.extend_from_slice(&self.ramdisk);
                pad(&mut out, PAGE);
                Ok(out)
            }
            Header::V0(h) => {
                let mut header: HeaderV0 = h.clone();
                header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                header.second_bootloader_size = u32::try_from(self.second.len()).context("second stage bootloader size")?;
                match &mut header.versioned {
                    HeaderV0Versioned::V0 => {}
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => {
                        *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery DTBO size")?;
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => {
                        *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery DTBO size")?;
                        *dtb_size = u32::try_from(self.dtb.len()).context("DTB size")?;
                    }
                }
                let parts: [&[u8]; 5] = [&self.kernel, &self.ramdisk, &self.second, &self.recovery_dtbo, &self.dtb];
                header.hash_digest = sections_digest(&parts);
                let page = header.page_size as usize;
                ensure!(page.is_power_of_two() && page >= 512, "a page size of {page} bytes is no boot image's");
                let mut out = Vec::new();
                Header::V0(header).write(&mut out).context("write header")?;
                pad(&mut out, page);
                for part in parts {
                    out.extend_from_slice(part);
                    pad(&mut out, page);
                }
                Ok(out)
            }
        }
    }
}

fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}
