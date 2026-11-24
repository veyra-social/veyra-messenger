// Unit-test fixtures. All hosts use the reserved .example domain.
const OFFICIAL_BOOTSTRAP_SEEDS: &[OfficialBootstrapSeed] = &[
    OfficialBootstrapSeed {
        id: "test-alpha",
        node_name: "alpha",
        peer_id: "12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs",
        multiaddrs_json: r#"[
  "/dns4/alpha.example/tcp/4001/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs",
  "/dns4/alpha.example/tcp/443/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs",
  "/dns4/alpha.example/udp/443/quic-v1/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs"
]"#,
        turn_urls: &[],
    },
    OfficialBootstrapSeed {
        id: "test-beta",
        node_name: "beta",
        peer_id: "12D3KooWBn5GZ7UJVi6GYPWZ9WkDeNBGLyfQjx9QyE69Eru7wPVz",
        multiaddrs_json: r#"[
  "/dns4/beta.example/tcp/4001/p2p/12D3KooWBn5GZ7UJVi6GYPWZ9WkDeNBGLyfQjx9QyE69Eru7wPVz",
  "/dns4/beta.example/tcp/443/p2p/12D3KooWBn5GZ7UJVi6GYPWZ9WkDeNBGLyfQjx9QyE69Eru7wPVz",
  "/dns4/beta.example/udp/443/quic-v1/p2p/12D3KooWBn5GZ7UJVi6GYPWZ9WkDeNBGLyfQjx9QyE69Eru7wPVz"
]"#,
        turn_urls: &[],
    },
    OfficialBootstrapSeed {
        id: "test-gamma",
        node_name: "gamma",
        peer_id: "12D3KooWQXHF676YqaRAwPnyPT51W5xqzYTAgvvjiMaNMUeAq5xf",
        multiaddrs_json: r#"[
  "/dns4/gamma.example/tcp/443/tls/ws/p2p/12D3KooWQXHF676YqaRAwPnyPT51W5xqzYTAgvvjiMaNMUeAq5xf",
  "/dns4/gamma.example/tcp/4001/p2p/12D3KooWQXHF676YqaRAwPnyPT51W5xqzYTAgvvjiMaNMUeAq5xf",
  "/dns4/gamma.example/udp/443/quic-v1/p2p/12D3KooWQXHF676YqaRAwPnyPT51W5xqzYTAgvvjiMaNMUeAq5xf"
]"#,
        turn_urls: &["turn:gamma.example:3478?transport=udp"],
    },
];

const RETIRED_SEED_IDS: &[&str] = &["test-retired"];
