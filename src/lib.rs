pub use crate::error::{Error, Result};

use std::collections::HashSet;
use std::fs;
use std::os::unix;
use std::path::{Path, PathBuf};

use log::warn;
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use regex::Regex;

mod error;

/// Rehashes a directory
///
/// Removes hash symlinks and broken symlinks (unlike openssl rehash) in
/// the directory, then for each certificate (or symlink to a certificate) in
/// the directory, creates a SHA1 hash symlink with a relative path to the
/// certificate.
///
/// Returns an error if there are any I/O failures due to filesystem access or
/// certificate deserialization
///
/// NOTE: CRL hash symlinks are not yet supported
///
/// # Examples
///
/// ```no_run
/// openssl_rehash::rehash("/etc/ssl/certs").unwrap();
/// ```
pub fn rehash(dir: impl AsRef<Path>) -> Result<()> {
    let mut seen_fingerprints: HashSet<Vec<u8>> = HashSet::new();

    for entry in clean_dir(dir.as_ref())? {
        if let Ok(Some(certificate)) = read_single_certificate(&entry) {
            let fingerprint = certificate.digest(MessageDigest::sha1())?;

            if !seen_fingerprints.contains(&*fingerprint) {
                seen_fingerprints.insert(fingerprint.to_vec());
                hash_link(&entry, certificate.subject_name_hash())?;
            } else {
                let path_display = entry.display();
                warn!("rehash: skipping duplicate certificate in {path_display}");
            }
        } else {
            let path_display = entry.display();
            warn!("rehash: skipping {path_display}, it does not contain exactly one certificate");
        }
    }

    Ok(())
}

/// Returns the directory's entries after any broken or hash symlinks are removed
fn clean_dir(dir: impl AsRef<Path>) -> std::io::Result<Vec<PathBuf>> {
    let mut entries: Vec<PathBuf> = vec![];
    let regex = Regex::new(r"^[[:xdigit:]]{8}\.\d+$").unwrap();

    for entry in fs::read_dir(dir.as_ref())? {
        let entry = entry?;
        let path = entry.path();
        if path.is_symlink() {
            if let Ok(false) = path.try_exists() {
                fs::remove_file(&path)?;
            } else if regex.is_match(&entry.file_name().to_string_lossy()) {
                fs::remove_file(&path)?;
            } else {
                entries.push(path);
            }
        } else {
            entries.push(path);
        }
    }

    entries.sort();

    Ok(entries)
}

fn read_single_certificate(path: impl AsRef<Path>) -> Result<Option<X509>> {
    let data = std::fs::read(path)?;
    match X509::stack_from_pem(&data) {
        Ok(x509) if x509.len() == 1 => Ok(Some(x509[0].clone())),
        // DER format cannot contain more than one certificate
        _ => Ok(Some(X509::from_der(&data)?)),
    }
}

/// Creates a symlink named after the hex representation of the name hash that
/// points to the target.
///
/// If a symlink with the same name already exists but points to a different
/// target, then the count on the file extension is incremented.
fn hash_link(target_path: impl AsRef<Path>, hash: u32) -> Result<()> {
    let target_path = target_path.as_ref();
    let parent_dir = target_path.parent().unwrap();
    let link_name = parent_dir.join(hash_link_stem(hash));
    let mut count = 0;

    loop {
        let link_path = link_name.with_extension(format!("{count}"));

        if link_path.is_symlink() {
            if link_path.try_exists()? {
                if link_path.read_link()? == target_path {
                    return Ok(());
                } else {
                    count += 1;
                }
            } else {
                fs::remove_file(&link_path)?;
            }
        } else {
            unix::fs::symlink(target_path.file_name().unwrap(), &link_path)?;
            break;
        }
    }

    Ok(())
}

fn hash_link_stem(hash: u32) -> String {
    format!("{:08x}", hash)
}

#[cfg(test)]
mod test {
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix;
    use std::path::Path;

    use insta::assert_debug_snapshot;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509Name, X509},
    };
    use tempfile::{tempdir, NamedTempFile};

    use super::*;

    /// tests rehash hashes a cert directory correctly
    ///
    /// The directory originally contains a cert bundle and two cert links
    /// pointing to the same physical cert
    ///
    /// The result hash directory should contain the exact same entries and a
    /// hash link pointing to the first cert link
    #[test]
    fn test_rehash() {
        let cert = build_x509("foo");
        let hash = format!("{:x}", cert.subject_name_hash());
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(&cert.to_pem().unwrap()).unwrap();
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_owned();
        let hash_link = cert_dir.join(hash).with_extension("0");
        let cert_link_0 = cert_dir.join("cert-link_0.crt");
        unix::fs::symlink(cert_file.path(), &cert_link_0).unwrap();
        let cert_link_1 = cert_dir.join("cert-link_1.crt");
        unix::fs::symlink(cert_file.path(), cert_link_1).unwrap();
        let mut cert_bundle = File::create(cert_dir.join("ca-certificates.crt")).unwrap();
        cert_bundle
            .write_all(&build_x509("bar").to_pem().unwrap())
            .unwrap();
        cert_bundle
            .write_all(&build_x509("baz").to_pem().unwrap())
            .unwrap();

        rehash(&cert_dir).unwrap();

        let mut dir_entries: Vec<String> = vec![];
        for entry in fs::read_dir(&cert_dir).unwrap() {
            let entry = entry.unwrap();
            dir_entries.push(entry.file_name().to_string_lossy().into());
        }
        dir_entries.sort();
        assert_debug_snapshot!(&dir_entries);

        assert_eq!(
            hash_link.read_link().unwrap(),
            Path::new(cert_link_0.file_name().unwrap())
        );
    }

    #[test]
    fn test_clean_links_on_empty_dir() {
        let tempdir = tempdir().unwrap();
        let cert_dir = tempdir.path().to_owned();

        let result = clean_dir(cert_dir).unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_clean_links_removes_hash_links() {
        // setup a cert dir with symlinks that point to a "physical cert" that
        // was removed
        let cert_file = NamedTempFile::new().unwrap();
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_owned();
        let cert_link_0 = cert_dir.join("cert-link_0.crt");
        let cert_link_1 = cert_dir.join("cert-link_1.crt");
        unix::fs::symlink(cert_file.path(), &cert_link_0).unwrap();
        unix::fs::symlink(cert_file.path(), &cert_link_1).unwrap();
        let hash_link_0 = cert_dir.join("12345678.0");
        let hash_link_1 = cert_dir.join("12345678.1");
        unix::fs::symlink(&cert_link_0, &hash_link_0).unwrap();
        unix::fs::symlink(&cert_link_1, &hash_link_1).unwrap();

        clean_dir(cert_dir).unwrap();

        assert!(!hash_link_0.exists() && !hash_link_1.exists());
    }

    #[test]
    fn test_clean_links_removes_broken_links() {
        // setup a cert dir with symlinks that point to a "physical cert" that
        // was removed
        let cert_file = NamedTempFile::new().unwrap();
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_owned();
        let broken_link_0 = cert_dir.join("broken-link_0.crt");
        let broken_link_1 = cert_dir.join("broken-link_1.crt");
        unix::fs::symlink(cert_file.path(), &broken_link_0).unwrap();
        unix::fs::symlink(cert_file.path(), &broken_link_1).unwrap();
        // break the links
        fs::remove_file(cert_file.path()).unwrap();

        clean_dir(cert_dir).unwrap();

        assert!(!broken_link_0.exists() && !broken_link_1.exists());
    }

    #[test]
    fn test_clean_links_keeps_unbroken_links() {
        // setup a cert dir with a symlink that points to a "physical cert"
        let temp_file = NamedTempFile::new().unwrap();
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_owned();
        let cert_link = cert_dir.join("cert-link.crt");
        unix::fs::symlink(temp_file.path(), &cert_link).unwrap();

        clean_dir(cert_dir).unwrap();

        assert!(cert_link.exists());
    }

    #[test]
    fn test_hash_link() {
        // setup a cert dir with a symlink that points to a "physical cert"
        let temp_file = NamedTempFile::new().unwrap();
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_owned();
        let cert_link = cert_dir.join("cert-link.crt");
        unix::fs::symlink(temp_file.path(), &cert_link).unwrap();
        let hash: u32 = 12345678;
        let hash_link_stem = hash_link_stem(hash);
        let hash_link_path = cert_dir.join(hash_link_stem).with_extension("0");

        hash_link(&cert_link, hash).unwrap();

        assert_eq!(
            hash_link_path.read_link().unwrap(),
            Path::new(cert_link.file_name().unwrap())
        );
    }

    #[test]
    fn test_hash_link_does_not_duplicate() {
        // setup a cert dir with a symlink that points to a "physical cert"
        // Additionally, setup a hash link that points to the cert link
        let temp_file = NamedTempFile::new().unwrap();
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_owned();
        let cert_link = cert_dir.join("cert-link.crt");
        unix::fs::symlink(temp_file.path(), &cert_link).unwrap();
        let hash: u32 = 12345678;
        let hash_link_stem = hash_link_stem(hash);
        let hash_link_0 = cert_dir.join(hash_link_stem).with_extension("0");

        unix::fs::symlink(&cert_link, &hash_link_0).unwrap();

        let hash_link_1 = hash_link_0.with_extension("1");

        hash_link(&cert_link, hash).unwrap();

        assert!(!hash_link_1.exists());
    }

    #[test]
    fn test_hash_link_resolves_collision() {
        // setup a cert dir with two symlinks that points to distinct "physical
        // certs" that have subject names which hash to the same value.
        // Additionally, setup a hash link that points one of the cert links
        let temp_file = NamedTempFile::new().unwrap();
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_owned();
        let cert_link_0 = cert_dir.join("cert-link_0.crt");
        unix::fs::symlink(temp_file.path(), &cert_link_0).unwrap();
        let cert_link_1 = cert_dir.join("cert-link_1.crt");
        unix::fs::symlink(temp_file.path(), &cert_link_1).unwrap();
        let hash: u32 = 12345678;
        let hash_link_stem = hash_link_stem(hash);
        let hash_link_0 = cert_dir.join(hash_link_stem).with_extension("0");
        unix::fs::symlink(&cert_link_0, &hash_link_0).unwrap();
        let hash_link_1 = hash_link_0.with_extension("1");

        hash_link(&cert_link_1, hash).unwrap();

        assert_eq!(
            hash_link_1.read_link().unwrap(),
            Path::new(cert_link_1.file_name().unwrap())
        );
    }

    fn build_x509(cn: &str) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        builder.build()
    }
}
