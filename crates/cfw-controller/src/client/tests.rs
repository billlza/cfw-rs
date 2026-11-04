use super::*;
use crate::test_support::FakeController;

mod delays;
mod limits;
mod requests;
mod transport;

const PROBE_URL: &str = "https://cp.cloudflare.com/generate_204";

fn request_lines(fixture: &FakeController) -> Vec<String> {
    fixture
        .requests()
        .iter()
        .map(|request| format!("{} {}", request.method, request.target))
        .collect()
}
