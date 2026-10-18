//! Read-only integration check. The network name and addresses stay private.
fn main() -> anyhow::Result<()> {
    match cfw_platform::current_network_context()? {
        Some(network) => println!(
            "physical_network={:?} interface={} ssid_available={} address_count={}",
            network.kind,
            network.interface,
            network.ssid.is_some(),
            network.addresses.len()
        ),
        None => println!("physical_network=disconnected"),
    }
    Ok(())
}
