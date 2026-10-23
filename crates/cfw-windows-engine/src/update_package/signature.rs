use super::{AuthenticodePublisher, HeldFile, PackageError, Result, combine, wide_path};
use sha2::{Digest, Sha256};
use std::{
    mem::size_of,
    os::windows::io::AsRawHandle,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, INVALID_HANDLE_VALUE},
    Security::{
        Cryptography::{
            CryptEncodeObjectEx, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        },
        WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
            WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrustEx,
        },
    },
};

pub(super) fn verify(file: &HeldFile) -> Result<AuthenticodePublisher> {
    let path = wide_path(&file.path)?;
    let mut information = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.file()?.as_raw_handle(),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut information,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: the sized SDK structures, terminated path and retained file handle
    // remain live through verification and CLOSE. This call never displays UI.
    let status = unsafe { WinVerifyTrustEx(INVALID_HANDLE_VALUE, &mut action, &mut data) };
    let result = if status == 0 {
        publisher(&data)
    } else {
        // WinVerifyTrust returns LONG: only zero is success, not SUCCEEDED(hr).
        Err(PackageError::Signature(status))
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: every VERIFY, including a failed one, is paired with CLOSE while
    // the same input structures and provider state remain live.
    let closed = unsafe { WinVerifyTrustEx(INVALID_HANDLE_VALUE, &mut action, &mut data) };
    combine(
        result,
        if closed == 0 {
            Ok(())
        } else {
            Err(PackageError::Signature(closed))
        },
    )
}

fn publisher(data: &WINTRUST_DATA) -> Result<AuthenticodePublisher> {
    if data.hWVTStateData.is_null() {
        return Err(PackageError::Invalid("Authenticode provider state"));
    }
    // SAFETY: this is a live state handle from successful WinVerifyTrust. The
    // provider owns the entire returned chain until the caller performs CLOSE.
    let provider = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
    if provider.is_null() {
        return Err(PackageError::Invalid("Authenticode provider"));
    }
    // SAFETY: provider is a non-null live provider; select the primary signer,
    // not a timestamp countersigner.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    // SAFETY: as_ref checks null; the SDK owns an aligned CRYPT_PROVIDER_SGNR.
    let signer = unsafe { signer.as_ref() }.ok_or(PackageError::Invalid("Authenticode signer"))?;
    if signer.cbStruct < size_of_val(signer) as u32
        || signer.dwError != 0
        || signer.csCertChain == 0
        || signer.pasCertChain.is_null()
    {
        return Err(PackageError::Invalid("Authenticode signer chain"));
    }
    // SAFETY: a nonempty, provider-owned certificate chain has a first entry.
    let certificate = unsafe { &*signer.pasCertChain };
    if certificate.cbStruct < size_of_val(certificate) as u32 || certificate.dwError != 0 {
        return Err(PackageError::Invalid("Authenticode signing certificate"));
    }
    // SAFETY: the certificate context and its info are provider-owned; check
    // each optional pointer before reading it.
    let context = unsafe { certificate.pCert.as_ref() }
        .ok_or(PackageError::Invalid("Authenticode certificate context"))?;
    // SAFETY: same provider lifetime as context.
    let info = unsafe { context.pCertInfo.as_ref() }.ok_or(PackageError::Invalid(
        "Authenticode certificate information",
    ))?;
    if info.SubjectPublicKeyInfo.PublicKey.cbData == 0 {
        return Err(PackageError::Invalid("Authenticode public key"));
    }
    let key = &info.SubjectPublicKeyInfo;
    let mut size = 0;
    // SAFETY: X509_PUBLIC_KEY_INFO expects CERT_PUBLIC_KEY_INFO. A null output
    // requests its DER size; the provider keeps the input alive.
    if unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            std::ptr::from_ref(key).cast(),
            0,
            null(),
            null_mut(),
            &mut size,
        )
    } == 0
    {
        return Err(last_error("measure publisher public key"));
    }
    if size == 0 || size > 16 * 1024 {
        return Err(PackageError::Invalid("publisher public key size"));
    }
    let mut der = vec![0u8; size as usize];
    // SAFETY: the measured, bounded output buffer has exactly size bytes.
    if unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            std::ptr::from_ref(key).cast(),
            0,
            null(),
            der.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(last_error("encode publisher public key"));
    }
    if size as usize != der.len() {
        return Err(PackageError::Invalid("publisher public key encoding size"));
    }
    Ok(AuthenticodePublisher {
        spki_sha256: Sha256::digest(der).into(),
    })
}

fn last_error(operation: &'static str) -> PackageError {
    // SAFETY: read the thread-local error immediately after the failed call.
    PackageError::Native {
        operation,
        code: unsafe { GetLastError() },
    }
}
