//! The rule set.
//!
//! Two rule sets, in two places, with two tasks:
//!
//! - [`HostRules`] lies in the node's network and decides what may pass the
//!   bridge. It protects the host and the outside world.
//! - [`NetnsRules`] lies **in a workload instance's namespace** and redirects
//!   its traffic to the sidecar. It authorizes nothing.
//!
//! # What is expressly *not* decided here
//!
//! Who may talk to whom. That stands in the `may_talk` edges and is enforced
//! in the mTLS handshake, by **identity**, not by address. A packet filter
//! that tried to answer the same question by IP addresses would be a second,
//! weaker enforcement in a place where one would later take it for the actual
//! one.
//!
//! The rule set therefore lets containers through among themselves. It sees to
//! it that the traffic reaches the sidecar at all — the permission is granted
//! there by a certificate.
//!
//! # The host stays the host
//!
//! The `forward` chain carries `policy accept` and refuses expressly. That looks
//! careless and is the opposite: a base chain on the `forward` hook applies to
//! **all** forwarded traffic of the machine. A `policy drop` there would tear
//! down every VM bridge and every foreign network, and nobody would look for the
//! error at the container orchestrator. That is why the first rule releases
//! everything that does not touch our own bridge.

use std::borrow::Cow;
use std::net::Ipv4Addr;

use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix};
use nftables::schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table};
use nftables::stmt::{Counter, Match, NAT, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

use crate::ipam::{ClusterNet, NodeSubnet};

pub const TABLE: &str = "tardigrade";

pub const FAMILY: &str = "inet";

pub use tg_model::mesh::{SIDECAR_EGRESS, SIDECAR_INBOUND, SIDECAR_OUTBOUND};

const FORWARD: &str = "forward";
const POSTROUTING: &str = "postrouting";

const FILTER_OUT: &str = "filter-out";

const FILTER_IN: &str = "filter-in";
const OUTPUT: &str = "output";
const PREROUTING: &str = "prerouting";

fn table() -> Table<'static> {
    Table {
        family: NfFamily::INet,
        name: Cow::Borrowed(TABLE),
        handle: None,
    }
}

fn base_chain(
    name: &'static str,
    kind: NfChainType,
    hook: NfHook,
    prio: i32,
    policy: NfChainPolicy,
) -> Chain<'static> {
    Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(TABLE),
        name: Cow::Borrowed(name),
        newname: None,
        handle: None,
        _type: Some(kind),
        hook: Some(hook),
        prio: Some(prio),
        dev: None,
        policy: Some(policy),
    }
}

fn rule(chain: &'static str, statements: Vec<Statement<'static>>) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(TABLE),
        chain: Cow::Borrowed(chain),
        expr: Cow::Owned(statements),
        handle: None,
        index: None,
        comment: None,
    }
}

fn meta(key: MetaKey) -> Expression<'static> {
    Expression::Named(NamedExpression::Meta(Meta { key }))
}

fn field(protocol: &'static str, name: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: Cow::Borrowed(protocol),
            field: Cow::Borrowed(name),
        },
    )))
}

fn prefix(addr: Ipv4Addr, len: u32) -> Expression<'static> {
    Expression::Named(NamedExpression::Prefix(Prefix {
        addr: Box::new(Expression::String(Cow::Owned(addr.to_string()))),
        len,
    }))
}

fn matches(
    left: Expression<'static>,
    op: Operator,
    right: Expression<'static>,
) -> Statement<'static> {
    Statement::Match(Match { left, right, op })
}

fn text(value: &str) -> Expression<'static> {
    Expression::String(Cow::Owned(value.to_owned()))
}

#[derive(Debug, Clone)]
pub struct HostRules {
    cluster: Ipv4Addr,
    cluster_len: u32,
    bridge: String,
}

impl HostRules {
    #[must_use]
    pub fn new(cluster: &ClusterNet, subnet: &NodeSubnet) -> Self {
        let _ = subnet;
        Self {
            cluster: cluster.net().network(),
            cluster_len: u32::from(cluster.net().prefix_len()),
            bridge: crate::ipam::BRIDGE.to_owned(),
        }
    }

    #[must_use]
    pub fn forward_policy(&self) -> &'static str {
        "accept"
    }

    fn forward_rules(&self) -> Vec<Vec<Statement<'static>>> {
        let on_bridge = |key: MetaKey, op: Operator| matches(meta(key), op, text(&self.bridge));

        vec![
            // 1. What does not touch our bridge is none of our business. This
            //    rule stands first, so that the orchestrator does not become the
            //    host firewall.
            vec![
                on_bridge(MetaKey::Iifname, Operator::NEQ),
                on_bridge(MetaKey::Oifname, Operator::NEQ),
                Statement::Return(None),
            ],
            // 2. Reply traffic. Without it every outgoing connection would be
            //    one-sided.
            vec![
                matches(
                    Expression::Named(NamedExpression::CT(nftables::expr::CT {
                        key: Cow::Borrowed("state"),
                        family: None,
                        dir: None,
                    })),
                    Operator::IN,
                    Expression::List(vec![text("established"), text("related")]),
                ),
                Statement::Accept(None),
            ],
            // 3. Containers among themselves. Who **may** talk to whom does not
            //    stand here but in the certificate.
            vec![
                on_bridge(MetaKey::Iifname, Operator::EQ),
                on_bridge(MetaKey::Oifname, Operator::EQ),
                Statement::Accept(None),
            ],
            // 4. Containers of **another** node, through the tunnel.
            //
            //    Without this rule every packet that arrived on `tgwg0` and went
            //    to one of our own containers fell into the `drop` below: the
            //    return direction was permitted (rule 5, `iifname tg0`), the
            //    forward direction was not. Measured on real packets between two
            //    nodes (`tests/two_nodes.rs`), **no** container thereby reached
            //    a container on another node — although anti-affinity spreads
            //    instances across racks by default and the underlay is built
            //    for exactly that traffic.
            //
            //    The tunnel is not "outside": `WireGuard` authenticates the peer
            //    and checks its `AllowedIPs`, so the source is a container of a
            //    node the cluster knows. Who **may** talk to whom is still
            //    decided by the certificate in the sidecar and not by the
            //    packet filter — the same division of labour rule 3 already
            //    makes for two containers on the same node.
            vec![
                matches(
                    meta(MetaKey::Iifname),
                    Operator::EQ,
                    text(crate::wireguard::DEVICE),
                ),
                on_bridge(MetaKey::Oifname, Operator::EQ),
                Statement::Accept(None),
            ],
            // 5. Containers outwards.
            vec![
                on_bridge(MetaKey::Iifname, Operator::EQ),
                Statement::Accept(None),
            ],
            // 6. Everything else that touches the bridge — that is, from
            //    outside in, without an existing connection and not through the
            //    tunnel.
            vec![Statement::Drop(None)],
        ]
    }

    #[must_use]
    pub fn forward_statements(&self) -> Vec<String> {
        describe(&self.forward_rules())
    }

    #[must_use]
    pub fn render(&self) -> Nftables<'static> {
        let mut objects = vec![
            // Delete first, then rebuild — in **one** file, so that no state
            // without rules lies between the two.
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table()))),
            NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(table()))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table()))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(base_chain(
                FORWARD,
                NfChainType::Filter,
                NfHook::Forward,
                0,
                NfChainPolicy::Accept,
            )))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(base_chain(
                POSTROUTING,
                NfChainType::NAT,
                NfHook::Postrouting,
                100,
                NfChainPolicy::Accept,
            )))),
        ];

        for statements in self.forward_rules() {
            objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule(
                FORWARD, statements,
            )))));
        }

        // Traffic from the cluster that leaves it gets the node's address.
        // Without that no answer would come back — the underlay does not know
        // the container subnets: WireGuard *is* the flat L3, the physical
        // network does not route them.
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule(
            POSTROUTING,
            vec![
                matches(
                    field("ip", "saddr"),
                    Operator::EQ,
                    prefix(self.cluster, self.cluster_len),
                ),
                matches(
                    field("ip", "daddr"),
                    Operator::NEQ,
                    prefix(self.cluster, self.cluster_len),
                ),
                Statement::Masquerade(None),
            ],
        )))));

        Nftables {
            objects: Cow::Owned(objects),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetnsRules {
    cluster: Ipv4Addr,
    cluster_len: u32,
    gateway: Ipv4Addr,
    sidecar_uid: u32,
    inbound: u16,
    outbound: u16,
    egress: Option<u16>,
    quic: Vec<u16>,
    udp: Vec<(std::net::Ipv4Addr, u16)>,
    mesh_udp: Vec<(std::net::Ipv4Addr, u16)>,
}

impl NetnsRules {
    #[must_use]
    pub fn new(cluster: &ClusterNet, subnet: &NodeSubnet, sidecar_uid: u32) -> Self {
        Self {
            cluster: cluster.net().network(),
            cluster_len: u32::from(cluster.net().prefix_len()),
            gateway: subnet.gateway(),
            sidecar_uid,
            inbound: SIDECAR_INBOUND,
            outbound: SIDECAR_OUTBOUND,
            egress: None,
            quic: Vec::new(),
            udp: Vec::new(),
            mesh_udp: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_egress(mut self, port: u16) -> Self {
        self.egress = Some(port);
        self
    }

    #[must_use]
    pub fn with_mesh_udp(mut self, peers: &[(std::net::Ipv4Addr, u16)]) -> Self {
        self.mesh_udp = peers.to_vec();
        self.mesh_udp.sort_unstable();
        self.mesh_udp.dedup();
        self
    }

    #[must_use]
    pub fn with_quic(mut self, ports: &[u16]) -> Self {
        self.quic = ports.to_vec();
        self.quic.sort_unstable();
        self.quic.dedup();
        self
    }

    #[must_use]
    pub fn with_udp(mut self, targets: &[(std::net::Ipv4Addr, u16)]) -> Self {
        self.udp = targets.to_vec();
        self.udp.sort_unstable();
        self.udp.dedup();
        self
    }

    fn established() -> Vec<Statement<'static>> {
        vec![
            matches(
                Expression::Named(NamedExpression::CT(nftables::expr::CT {
                    key: Cow::Borrowed("state"),
                    family: None,
                    dir: None,
                })),
                Operator::IN,
                Expression::List(vec![text("established"), text("related")]),
            ),
            Statement::Accept(None),
        ]
    }

    fn counted_drop() -> Vec<Statement<'static>> {
        vec![
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Drop(None),
        ]
    }

    fn outbound_rules(&self) -> Vec<Vec<Statement<'static>>> {
        let mut rules = vec![
            // 1. The sidecar itself. **Must** stand before the redirect,
            //    otherwise it redirects its own traffic onto itself — a loop
            //    that appears as a timeout and not as a rule error.
            vec![
                matches(
                    meta(MetaKey::Skuid),
                    Operator::EQ,
                    Expression::Number(self.sidecar_uid),
                ),
                Statement::Return(None),
            ],
            // 2. Loopback. The sidecar addresses its workload over 127.0.0.1;
            //    if that were redirected, it would talk to itself.
            vec![
                matches(
                    field("ip", "daddr"),
                    Operator::EQ,
                    prefix(Ipv4Addr::new(127, 0, 0, 0), 8),
                ),
                Statement::Return(None),
            ],
            // 3. The node itself is no mesh target. The resolver listens
            //    there, and DNS over TCP does not belong in the sidecar.
            vec![
                matches(
                    field("ip", "daddr"),
                    Operator::EQ,
                    text(&self.gateway.to_string()),
                ),
                Statement::Return(None),
            ],
            // 4. What goes into the cluster goes through the sidecar.
            vec![
                matches(meta(MetaKey::L4proto), Operator::EQ, text("tcp")),
                matches(
                    field("ip", "daddr"),
                    Operator::EQ,
                    prefix(self.cluster, self.cluster_len),
                ),
                Statement::Redirect(Some(NAT {
                    addr: None,
                    family: None,
                    port: Some(Expression::Number(u32::from(self.outbound))),
                    flags: None,
                })),
            ],
        ];

        // 5. Everything else is egress, and the policy is deny-by-default
        //    with the sidecar as the only way out.
        //
        //    The rule stands **behind** the cluster rule: what goes into the
        //    mesh is already redirected and no longer arrives here. And it
        //    stands behind the exception for the sidecar itself — otherwise its
        //    own call outwards would be redirected back to it.
        if let Some(egress) = self.egress {
            rules.push(vec![
                matches(meta(MetaKey::L4proto), Operator::EQ, text("tcp")),
                Statement::Redirect(Some(NAT {
                    addr: None,
                    family: None,
                    port: Some(Expression::Number(u32::from(egress))),
                    flags: None,
                })),
            ]);
        }

        // 5a. **UDP in the mesh.** **Before the QUIC egress rule below**, and
        //     that is the order that counts here: both are UDP. A peer in the
        //     cluster on a port that is permitted outwards (`:443`, say)
        //     would otherwise go out instead of into the mesh — and the
        //     egress way splices by an SNI that a QUIC datagram in the mesh
        //     does not carry.
        //
        //     To the egress rule above, the order is by contrast irrelevant:
        //     that one carries `l4proto == tcp` and cannot hit a datagram.
        //
        //     **One rule per peer, and the port carries the information.** With
        //     TCP the sidecar takes address and port from `SO_ORIGINAL_DST`;
        //     with UDP that does not exist, and a redirect leaves `127.0.0.1`
        //     of the destination address (measured). Which peer was meant
        //     stands afterwards **only** in the local port — so every peer
        //     gets its own.
        //
        //     **With** a port, unlike with the QUIC egress: there the redirect
        //     preserves the port, because it is the information. Here it is
        //     not — the address would be, and that is lost anyway.
        for (peer, local) in &self.mesh_udp {
            rules.push(vec![
                matches(meta(MetaKey::L4proto), Operator::EQ, text("udp")),
                matches(field("ip", "daddr"), Operator::EQ, text(&peer.to_string())),
                Statement::Redirect(Some(NAT {
                    addr: None,
                    family: None,
                    port: Some(Expression::Number(u32::from(*local))),
                    flags: None,
                })),
            ]);
        }

        // 6. QUIC. **Without a port**: the redirect rewrites the address to
        //    `127.0.0.1` and leaves the port standing — only so does the
        //    sidecar learn via `IP_RECVORIGDSTADDR` where the container
        //    wanted to go. With a port, the ancillary message measurably
        //    carries the port **after** the DNAT, and that is worthless.
        //
        //    One rule per permitted port, not one over all UDP: otherwise what
        //    the baseline discards would lie here too.
        for port in &self.quic {
            rules.push(vec![
                matches(meta(MetaKey::L4proto), Operator::EQ, text("udp")),
                matches(
                    field("udp", "dport"),
                    Operator::EQ,
                    Expression::Number(u32::from(*port)),
                ),
                Statement::Redirect(None),
            ]);
        }

        rules
    }

    fn filter_out_rules(&self) -> Vec<Vec<Statement<'static>>> {
        let mut rules = vec![
            // 1. Answers to what is permitted.
            Self::established(),
            // 2. **The redirect's target.** The nat chain runs on the same
            //    hook with priority -100, so **before** this one: a
            //    redirected packet already carries `127.0.0.1` as its
            //    destination here. Without this rule the mesh traffic would die
            //    at its own baseline.
            vec![
                matches(
                    field("ip", "daddr"),
                    Operator::EQ,
                    Expression::Named(NamedExpression::Prefix(Prefix {
                        addr: Box::new(text("127.0.0.0")),
                        len: 8,
                    })),
                ),
                Statement::Accept(None),
            ],
            // 3. **The sidecar dials out — and nobody else.** Without a
            //    sidecar process nobody carries this id, so the exception has
            //    no effect. With a sidecar it is the only door.
            //
            //    Under a user namespace it is the **mapped** id — the one the
            //    kernel sees.
            vec![
                matches(
                    meta(MetaKey::Skuid),
                    Operator::EQ,
                    Expression::Number(self.sidecar_uid),
                ),
                Statement::Accept(None),
            ],
            // 4. Our own node. Without the resolver no container would
            //    resolve a name, and the node is no mesh counterpart but the
            //    ground on which the instance stands.
            vec![
                matches(
                    field("ip", "daddr"),
                    Operator::EQ,
                    text(&self.gateway.to_string()),
                ),
                Statement::Accept(None),
            ],
            // 5. Everything else does not go out. **ICMP included**: a
            //    baseline that means "everything except through the sidecar"
            //    cannot make an exception for a protocol that does not pass
            //    through the sidecar — otherwise it would be a perimeter with
            //    a hole again. `ping` stays possible to the node (rule 4).
            Self::counted_drop(),
        ];

        // 4a. **Plain UDP to permitted targets** — inserted **before** the
        //     discard, otherwise the permission would have no effect: `nft`
        //     executes the rules in order.
        //
        //     Address **and** port: only the address would permit every service
        //     on that machine, only the port would permit it everywhere. And
        //     expressly only UDP — the same machine over TCP stays at the
        //     sidecar.
        let drop_at = rules.len() - 1;
        for (address, port) in &self.udp {
            rules.insert(
                drop_at,
                vec![
                    matches(
                        field("ip", "daddr"),
                        Operator::EQ,
                        text(&address.to_string()),
                    ),
                    matches(
                        field("udp", "dport"),
                        Operator::EQ,
                        Expression::Number(u32::from(*port)),
                    ),
                    Statement::Accept(None),
                ],
            );
        }

        rules
    }

    #[must_use]
    pub fn filter_out_statements(&self) -> Vec<String> {
        describe(&self.filter_out_rules())
    }

    fn filter_in_rules(&self) -> Vec<Vec<Statement<'static>>> {
        vec![
            // 1. Answers to what is permitted — **the place without which the
            //    sidecar would not get its own answers**.
            Self::established(),
            // 2. What was redirected to the sidecar. The nat prerouting chain
            //    runs before the routing, so the packet already carries the
            //    sidecar's port here.
            vec![
                matches(
                    field("ip", "daddr"),
                    Operator::EQ,
                    Expression::Named(NamedExpression::Prefix(Prefix {
                        addr: Box::new(text("127.0.0.0")),
                        len: 8,
                    })),
                ),
                Statement::Accept(None),
            ],
            vec![
                matches(meta(MetaKey::L4proto), Operator::EQ, text("tcp")),
                matches(
                    field("tcp", "dport"),
                    Operator::EQ,
                    Expression::Number(u32::from(self.inbound)),
                ),
                Statement::Accept(None),
            ],
            // 3. **The node in both directions.** The resolver's answer comes
            //    from there; and if the resolver lies in the same namespace — as
            //    in the harness — the query hits this chain too, with the node
            //    as the **destination**. Excepting only the source then let it
            //    drop.
            vec![
                matches(
                    field("ip", "saddr"),
                    Operator::EQ,
                    text(&self.gateway.to_string()),
                ),
                Statement::Accept(None),
            ],
            vec![
                matches(
                    field("ip", "daddr"),
                    Operator::EQ,
                    text(&self.gateway.to_string()),
                ),
                Statement::Accept(None),
            ],
            // 4. Everything else does not come in. Without a sidecar nobody
            //    listens on 15006 anyway, and **whoever has none is not
            //    reachable** — the server side is authoritative, and without
            //    a sidecar there is no authorization.
            Self::counted_drop(),
        ]
    }

    #[must_use]
    pub fn filter_in_statements(&self) -> Vec<String> {
        describe(&self.filter_in_rules())
    }

    fn inbound_rules(&self) -> Vec<Vec<Statement<'static>>> {
        vec![
            // What is already destined for the sidecar stays so.
            vec![
                matches(meta(MetaKey::L4proto), Operator::EQ, text("tcp")),
                matches(
                    field("tcp", "dport"),
                    Operator::EQ,
                    Expression::Number(u32::from(self.inbound)),
                ),
                Statement::Return(None),
            ],
            vec![
                matches(meta(MetaKey::L4proto), Operator::EQ, text("tcp")),
                Statement::Redirect(Some(NAT {
                    addr: None,
                    family: None,
                    port: Some(Expression::Number(u32::from(self.inbound))),
                    flags: None,
                })),
            ],
        ]
    }

    #[must_use]
    pub fn outbound_statements(&self) -> Vec<String> {
        describe(&self.outbound_rules())
    }

    #[must_use]
    pub fn inbound_statements(&self) -> Vec<String> {
        describe(&self.inbound_rules())
    }

    #[must_use]
    pub fn render_baseline(&self) -> Nftables<'static> {
        self.document(false)
    }

    #[must_use]
    pub fn render(&self) -> Nftables<'static> {
        self.document(true)
    }

    fn document(&self, with_redirect: bool) -> Nftables<'static> {
        let mut objects = vec![
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table()))),
            NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(table()))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table()))),
            // **Filter instead of NAT**: in a `nat` chain only the first
            // packet of a connection arrives, a `drop` did not belong there.
            // `policy accept`, and refusing happens **expressly** — the same
            // choice as with the node's rule set, for the same reason: a
            // policy that applies to everything eventually hits something
            // nobody meant.
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(base_chain(
                FILTER_OUT,
                NfChainType::Filter,
                NfHook::Output,
                0,
                NfChainPolicy::Accept,
            )))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(base_chain(
                FILTER_IN,
                NfChainType::Filter,
                NfHook::Input,
                0,
                NfChainPolicy::Accept,
            )))),
        ];

        if with_redirect {
            objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(
                base_chain(
                    OUTPUT,
                    NfChainType::NAT,
                    NfHook::Output,
                    -100,
                    NfChainPolicy::Accept,
                ),
            ))));
            objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(
                base_chain(
                    PREROUTING,
                    NfChainType::NAT,
                    NfHook::Prerouting,
                    -100,
                    NfChainPolicy::Accept,
                ),
            ))));
        }

        for statements in self.filter_out_rules() {
            objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule(
                FILTER_OUT, statements,
            )))));
        }
        for statements in self.filter_in_rules() {
            objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule(
                FILTER_IN, statements,
            )))));
        }

        if with_redirect {
            for statements in self.outbound_rules() {
                objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule(
                    OUTPUT, statements,
                )))));
            }
            for statements in self.inbound_rules() {
                objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule(
                    PREROUTING, statements,
                )))));
            }
        }

        Nftables {
            objects: Cow::Owned(objects),
        }
    }
}

fn describe(rules: &[Vec<Statement<'static>>]) -> Vec<String> {
    rules
        .iter()
        .map(|statements| {
            serde_json::to_string(statements).unwrap_or_else(|err| format!("<unreadable: {err}>"))
        })
        .collect()
}

pub fn to_json(ruleset: &Nftables<'_>) -> Result<String, serde_json::Error> {
    serde_json::to_string(ruleset)
}

#[must_use]
pub fn is_applied(rendered: &Nftables<'_>, listed: &str) -> bool {
    let Ok(want) = serde_json::to_value(rendered) else {
        return false;
    };
    let Ok(have) = serde_json::from_str::<serde_json::Value>(listed) else {
        // Unreadable means deviation — the safe direction: setting anew is
        // idempotent and atomic, doing nothing would be a conjecture.
        return false;
    };

    shape_of(&want, true) == shape_of(&have, false)
}

fn shape_of(document: &serde_json::Value, commands: bool) -> (Vec<String>, Vec<String>) {
    let mut chains = Vec::new();
    let mut rules = Vec::new();

    let objects = document
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    for object in objects {
        // With us the content stands under `add`; `delete` is skipped, for our
        // representation first clears away and then builds up — what stands
        // afterwards is the desired state.
        let inner = if commands {
            let Some(added) = object.get("add") else {
                continue;
            };
            added
        } else {
            object
        };

        if let Some(chain) = inner.get("chain").and_then(|chain| chain.get("name")) {
            chains.push(chain.to_string());
        }
        if let Some(rule) = inner.get("rule") {
            rules.push(format!(
                "{}|{}",
                rule.get("chain")
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                rule.get("expr").map(normalise).unwrap_or_default()
            ));
        }
    }

    (chains, rules)
}

fn normalise(expr: &serde_json::Value) -> String {
    let Some(items) = expr.as_array() else {
        return expr.to_string();
    };

    // Which protocols occur as a payload — those are the ones whose explicit
    // `l4proto` `nft` may strike.
    let payloads: Vec<&str> = items
        .iter()
        .filter_map(|item| {
            item.get("match")?
                .get("left")?
                .get("payload")?
                .get("protocol")?
                .as_str()
        })
        .collect();

    let kept: Vec<serde_json::Value> = items
        .iter()
        .filter(|item| !redundant_protocol(item, &payloads))
        .map(|item| {
            if item.get("counter").is_some() {
                serde_json::json!({ "counter": serde_json::Value::Null })
            } else {
                (*item).clone()
            }
        })
        .collect();

    serde_json::Value::Array(kept).to_string()
}

fn redundant_protocol(item: &serde_json::Value, payloads: &[&str]) -> bool {
    let Some(matched) = item.get("match") else {
        return false;
    };
    if matched
        .get("left")
        .and_then(|left| left.get("meta"))
        .and_then(|meta| meta.get("key"))
        != Some(&serde_json::Value::String("l4proto".to_owned()))
    {
        return false;
    }

    matched
        .get("right")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|protocol| payloads.contains(&protocol))
}
