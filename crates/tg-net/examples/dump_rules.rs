//! Emits the produced rule sets as JSON — for cross-reading with `nft`.
//!
//! `cargo run -p tg-net --example dump_rules -- host | nft --check -j -f -`

/// Renders the host or namespace rule set for a fixed example subnet and
/// prints it as JSON on standard output.
fn main() {
    let cluster = tg_net::ipam::ClusterNet::new("10.42.0.0/16".parse().unwrap(), 24).unwrap();
    let subnet = cluster.subnet(1).unwrap();

    let which = std::env::args().nth(1).unwrap_or_else(|| "host".to_owned());
    let json = match which.as_str() {
        "host" => {
            tg_net::rules::to_json(&tg_net::rules::HostRules::new(&cluster, &subnet).render())
        }
        "netns" => tg_net::rules::to_json(
            &tg_net::rules::NetnsRules::new(&cluster, &subnet, 4711).render(),
        ),
        other => {
            eprintln!("unknown: {other}");
            std::process::exit(2);
        }
    };

    println!("{}", json.expect("serializable"));
}
