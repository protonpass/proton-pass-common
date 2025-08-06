use super::EnteImportError;
use chacha20::cipher::{consts::U10, generic_array::GenericArray};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    hchacha, ChaCha20,
};
use poly1305::{universal_hash::KeyInit, Poly1305};

// Constants from the Go implementation
const TAG_MESSAGE: u8 = 0;
const TAG_PUSH: u8 = 0x01;
const TAG_REKEY: u8 = 0x02;
const TAG_FINAL: u8 = TAG_PUSH | TAG_REKEY;
const XCHACHA20POLY1305_IETF_ABYTES: usize = 17; // 16 + 1

pub fn decrypt_xchacha20poly1305(data: &[u8], key: &[u8; 32], header: &[u8]) -> Result<Vec<u8>, EnteImportError> {
    // Ensure header is 24 bytes for XChaCha20
    if header.len() != 24 {
        warn!("Header must be 24 bytes for XChaCha20");
        return Err(EnteImportError::BadContent);
    }

    if data.len() < XCHACHA20POLY1305_IETF_ABYTES {
        warn!("Data too short");
        return Err(EnteImportError::BadContent);
    }

    // Derive the subkey using HChaCha20 (same as Go's crypto_core_hchacha20)
    let chacha_key = chacha20::Key::from_slice(key);
    let hchacha_header = GenericArray::from_slice(&header[..16]);
    let subkey = hchacha::<U10>(chacha_key, hchacha_header);

    // Initialize nonce (same as Go's state initialization)
    let mut nonce = [0u8; 12];
    nonce[0] = 1; // counter starts at 1 (from reset())
                  // Copy the last 8 bytes of header to nonce[4..12] (INONCE part)
    nonce[4..12].copy_from_slice(&header[16..24]);

    let mlen = data.len() - XCHACHA20POLY1305_IETF_ABYTES;

    // Create ChaCha20 cipher (equivalent to chacha20.NewUnauthenticatedCipher)
    let mut cipher = ChaCha20::new(&subkey, &nonce.into());

    // Generate the first 64-byte block for Poly1305 key (block 0)
    let mut block = [0u8; 64];
    cipher.apply_keystream(&mut block);

    // Initialize Poly1305 with the first 32 bytes (same as Go's poly1305.New(&poly1305State))
    let poly_key: [u8; 32] = match block[..32].try_into() {
        Ok(key) => key,
        Err(e) => {
            warn!("Error converting block to key: {e:?}");
            return Err(EnteImportError::BadContent);
        }
    };
    let poly = Poly1305::new(&poly_key.into());

    // Process the tag block (block 1)
    block.fill(0); // memZero(block[:])
    block[0] = data[0]; // block[0] = cipher[0]

    // XORKeyStream with block 1
    if let Err(e) = cipher.try_apply_keystream(&mut block) {
        warn!("Error decrypting data on block 1: {e:?}");
        return Err(EnteImportError::BadContent);
    }

    let tag = block[0];
    block[0] = data[0]; // Restore original byte for MAC

    // Concatenate all data as Go does with sequential poly.Write() calls
    let c = &data[1..];
    let padlen = (0x10i32 - 64i32 + mlen as i32) & 0xf;
    let ad_len = 0u64.to_le_bytes();
    let total_len = (64u64 + mlen as u64).to_le_bytes();

    // Build the complete data stream as Go does
    let mut poly_data = Vec::new();
    poly_data.extend_from_slice(&block); // 64 bytes
    poly_data.extend_from_slice(&c[..mlen]); // mlen bytes
    if padlen > 0 {
        poly_data.extend(vec![0u8; padlen as usize]); // padlen bytes
    }
    poly_data.extend_from_slice(&ad_len); // 8 bytes
    poly_data.extend_from_slice(&total_len); // 8 bytes

    // Try using compute_unpadded since this is similar to XSalsa20Poly1305
    let computed_mac = poly.compute_unpadded(&poly_data);
    let stored_mac = &c[mlen..];

    if computed_mac.as_slice() != stored_mac {
        warn!("MAC mismatch. Usually due to wrong password");
        return Err(EnteImportError::BadPassword);
    }

    // Decrypt the message (block 2+)
    let mut plaintext = c[..mlen].to_vec();
    if let Err(e) = cipher.try_apply_keystream(&mut plaintext) {
        warn!("Error decrypting data on block 2: {e:?}");
        return Err(EnteImportError::BadContent);
    }

    // Validate tag (should be TAG_FINAL or TAG_MESSAGE for V2)
    if tag != TAG_FINAL && tag != TAG_MESSAGE {
        warn!("Invalid tag: {tag}");
        return Err(EnteImportError::BadContent);
    }

    Ok(plaintext)
}
