//! The bind request a fixture Desktop hands its restricted UserAgent on
//! standard input. The ticket never reaches a command line or a file.
use super::*;
use cfw_windows_engine::authority::wire::{MAX_MESSAGE_BYTES, Request};
use std::io::Read;
use zeroize::Zeroizing;

pub(super) fn read() -> Result<Request> {
    let mut bytes = Zeroizing::new(vec![0; MAX_MESSAGE_BYTES + 1]);
    let mut length = 0;
    let mut input = std::io::stdin().lock();
    while length < bytes.len() {
        let count = input
            .read(&mut bytes[length..])
            .map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        length += count;
    }
    Request::decode(&bytes[..length]).map_err(|e| e.to_string())
}
