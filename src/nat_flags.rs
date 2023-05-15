/// All of the flags within this module conform with NAT behaviors observed by rfc4787,
/// https://datatracker.ietf.org/doc/html/rfc4787.
///
/// By bitwise or'ing them together one can specify any combination of NAT behaviors.
/// These flags directly model NAT behaviors, however certain combinations can accurately emulate
/// common stateful firewall behaviors as well.
///
/// A NAT with a flag set to true is at least as "hard" to punch through as a NAT with the same flag
/// set to false. In other words, the more flags that are set to true for a NAT, the more misbehaved
/// and difficult to punch through the NAT becomes.
///
/// `0u32` as the set of flags specifies a simple NAT that will just perform address translation
/// for outgoing and incoming packets. It will avoid translating port numbers unless there is a port
/// number collision on outgoing packets, at which point it will choose the port number for one of
/// them randomly.
///
/// `0xffffffffu32` as the set of flags specifies the worst kind of symmetric enterprise NAT,
/// one which breaks nearly every requirement specified by rfc4787.
///
/// We also have a set of pre-defined flag combinations for common NAT types in the `predefines`
/// module. The `flags` module only needs to be used if you have extremely specific and uncommon NAT
/// behavior combinations you want to see.
pub mod flags {
    /// If true, the NAT has an "IP address pooling" behavior of "Arbitrary".
    ///
    /// By default the NAT has an "IP address pooling" behavior of "Paired".
    ///
    /// In "Paired" mode the NAT will always assign the same internal intranet address to the same
    /// external internet address.
    /// In "Arbitrary" mode the NAT will randomly assign an external internet address to every new
    /// outbound mapping.
    pub const IP_POOLING_BEHAVIOR_ARBITRARY: u32 = 1 << 0;

    /// If true, the NAT will generate a new outbound mapping for a given src_addr and
    /// src_port address whenever the dest_addr does not match the previous mappings.
    pub const ADDRESS_DEPENDENT_MAPPING: u32 = 1 << 1;
    /// If true, the NAT will generate a new outbound mapping for a given src_addr and
    /// src_port address whenever the dest_port does not match the previous mappings.
    pub const PORT_DEPENDENT_MAPPING: u32 = 1 << 2;
    /// If true, the NAT will do both address and port dependent mapping.
    pub const ADDRESS_AND_PORT_DEPENDENT_MAPPING: u32 = ADDRESS_DEPENDENT_MAPPING | PORT_DEPENDENT_MAPPING;

    /// If true, the NAT will drop incoming packets that do not have the same src_addr as the
    /// mapping for the given dest_addr and dest_port.
    pub const ADDRESS_DEPENDENT_FILTERING: u32 = 1 << 3;
    /// If true, the NAT will drop incoming packets that do not have the same src_port as the
    /// mapping for the given dest_addr and dest_port.
    pub const PORT_DEPENDENT_FILTERING: u32 = 1 << 4;
    /// If true, the NAT will do both address and port dependent filtering.
    pub const ADDRESS_AND_PORT_DEPENDENT_FILTERING: u32 = ADDRESS_DEPENDENT_FILTERING | PORT_DEPENDENT_FILTERING;

    /// If true, the NAT will not attempt to hairpin intranet to intranet packets and instead drop
    /// them.
    ///
    /// By default the NAT will always hairpin intranet to intranet packets, rewriting the
    /// src_addr and src_port to be the external internet address and port of the sender.
    pub const NO_HAIRPINNING: u32 = 1 << 5;
    /// If true, the NAT will attempt to hairpin intranet to intranet packets, but it will rewrite
    /// the src_addr and src_port to be the internal intranet address and port of the sender.
    ///
    /// This flag has no effect if `NO_HAIRPINNING` is true.
    pub const INTERNAL_ADDRESS_AND_PORT_HAIRPINNING: u32 = 1 << 6;

    /// If true, the NAT will not refresh the timeout on a mapping that just received an inbound
    /// packet. The intranet client behind the NAT will have to send "keep-alive" packets.
    pub const INBOUND_REFRESH_BEHAVIOR_FALSE: u32 = 1 << 8;
    /// If true, the NAT will not refresh the timeout on a mapping that just sent an outbound
    /// packet. The internet peer in front of the NAT will have to send "keep-alive" packets.
    ///
    /// If `INBOUND_REFRESH_BEHAVIOR_FALSE` is also true it is not possible for two peers to
    /// permanently keep a mapping open through this NAT.
    pub const OUTBOUND_REFRESH_BEHAVIOR_FALSE: u32 = 1 << 7;
    /// If true, if an inbound packet is filtered by the NAT, the NAT will also destroy any mappings
    /// connected to the dest_addr and dest_port specified by the inbound packet.
    pub const FILTERED_INBOUND_DESTROYS_MAPPING: u32 = 1 << 9;

    /// If true, the NAT will make no attempt to preserve the source port number of a outbound
    /// packet.
    /// For all outbound connections, internal ports will be mapped to a random external port.
    pub const NO_PORT_PRESERVATION: u32 = 1 << 10;
    /// If true, the NAT will make no attempt to preserve parity of the source port number of an
    /// outbound packet. Preserving port parity can help some protocols, as described in rfc4787.
    pub const NO_PORT_PARITY: u32 = 1 << 11;
    /// If true, the NAT will guarantee source port preservation by overwritting older mappings that
    /// are using the same combination of external address and source port as the newer mapping.
    ///
    /// This flag has no effect if `NO_PORT_PRESERVATION` is true.
    pub const PORT_PRESERVATION_OVERRIDE: u32 = 1 << 12;
    /// If true, the NAT will force source port preservation by allowing multiple intranet addresses
    /// to share a single port number.
    ///
    /// When an inbound packet is addressed to an overloaded port which intranet address will be
    /// sent this packet is decided nondeterministically. If address or port filtering are enabled
    /// the NAT will send the packet to some intranet address that matches the filtering.
    ///
    /// This flag has no effect if `NO_PORT_PRESERVATION` is true.
    pub const PORT_PRESERVATION_OVERLOAD: u32 = 1 << 13;
}
/// This is a set of pre-defined flags for common NAT types. Each constant represents some
/// common NAT or firewall types one might want to emulate with this library. These are provided for
/// convenience and are equivalent to manually bitwise-or'ing the relevant NAT flags together.
pub mod predefines {
    use super::flags::*;

    /// Equivalent to: `PORT_PRESERVATION_OVERRIDE`
    ///
    /// # Example
    /// ```
    /// use nat_emulation::predefines::STATEFUL_FIREWALL;
    /// use nat_emulation::{DestType, Nat};
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let client_addr = 11111;
    /// let client_port = 17;
    /// let server_addr = 22222;
    /// let server_port = 80;
    /// let mut firewall = Nat::no_address_translation(STATEFUL_FIREWALL, client_addr, rng, timeout);
    /// assert_eq!(firewall.assign_internal_address(), client_addr);
    ///
    /// time += 100;
    /// let translation = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time);
    /// assert!(translation.is_none());
    ///
    /// time += 100;
    /// match firewall.send_internal_packet(client_addr, client_port, server_addr, server_port, time) {
    ///     DestType::Internal { .. } => assert!(false),
    ///     DestType::Drop => assert!(false),
    ///     DestType::External { external_src_addr, external_src_port } => {
    ///         assert_eq!(external_src_addr, client_addr);
    ///         assert_eq!(external_src_port, client_port);
    ///     }
    /// }
    ///
    /// time += 100;
    /// let (internal_dest_addr, internal_dest_port) = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time).unwrap();
    /// assert_eq!(internal_dest_addr, client_addr);
    /// assert_eq!(internal_dest_port, client_port);
    ///
    /// time += timeout + 1;
    /// let translation = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time);
    /// assert!(translation.is_none());
    /// ```
    pub const STATEFUL_FIREWALL: u32 = PORT_PRESERVATION_OVERRIDE;
    /// Equivalent to: `STATEFUL_FIREWALL | ADDRESS_DEPENDENT_FILTERING`
    ///
    /// # Example
    /// ```
    /// use nat_emulation::predefines::RESTRICTED_FIREWALL;
    /// use nat_emulation::Nat;
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let client_addr = 11111;
    /// let client_port = 17;
    /// let server0_addr = 22222;
    /// let server1_addr = 33333;
    /// let server_port = 80;
    /// let mut firewall = Nat::no_address_translation(RESTRICTED_FIREWALL, client_addr, rng, timeout);
    /// assert_eq!(firewall.assign_internal_address(), client_addr);
    ///
    /// time += 100;
    /// let translation = firewall.send_internal_packet(client_addr, client_port, server0_addr, server_port, time);
    /// assert!(translation.is_external());
    ///
    /// time += 100;
    /// let translation = firewall.receive_external_packet(server1_addr, server_port, client_addr, client_port, false, time);
    /// assert!(translation.is_none());
    /// ```
    pub const RESTRICTED_FIREWALL: u32 = STATEFUL_FIREWALL | ADDRESS_DEPENDENT_FILTERING;
    /// Equivalent to: `STATEFUL_FIREWALL | ADDRESS_AND_PORT_DEPENDENT_FILTERING`
    ///
    /// # Example
    /// ```
    /// use nat_emulation::predefines::PORT_RESTRICTED_FIREWALL;
    /// use nat_emulation::Nat;
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let client_addr = 11111;
    /// let client_port = 2000;
    /// let server_addr = 22222;
    /// let server0_port = 80;
    /// let server1_port = 17;
    /// let mut firewall = Nat::no_address_translation(PORT_RESTRICTED_FIREWALL, client_addr, rng, timeout);
    ///
    /// assert_eq!(firewall.assign_internal_address(), client_addr);
    ///
    /// time += 100;
    /// let translation = firewall.send_internal_packet(client_addr, client_port, server_addr, server0_port, time);
    /// assert!(translation.is_external());
    ///
    /// time += 100;
    /// let translation = firewall.receive_external_packet(server_addr, server1_port, client_addr, client_port, false, time);
    /// assert!(translation.is_none());
    /// ```
    pub const PORT_RESTRICTED_FIREWALL: u32 = STATEFUL_FIREWALL | ADDRESS_AND_PORT_DEPENDENT_FILTERING;
    /// Equivalent to: `PORT_RESTRICTED_FIREWALL | PORT_PRESERVATION_OVERLOAD`
    pub const MISBEHAVING_FIREWALL: u32 = PORT_RESTRICTED_FIREWALL | PORT_PRESERVATION_OVERLOAD;

    /// Equivalent to not setting any flags: `0u32`
    ///
    /// # Example
    /// ```
    /// use nat_emulation::predefines::EASY_NAT;
    /// use nat_emulation::{DestType, Nat};
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let nat_ex_addr = 11111;
    /// let mut nat = Nat::new(EASY_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);
    /// let client_in_addr = nat.assign_internal_address();
    /// let client_in_port = 17;
    /// let server_ex_addr = 22222;
    /// let server_ex_port = 80;
    ///
    /// time += 100;
    /// let translation = nat.receive_external_packet(server_ex_addr, server_ex_port, nat_ex_addr, client_in_port, false, time);
    /// assert!(translation.is_none());
    ///
    /// time += 100;
    /// match nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port, time) {
    ///     DestType::Internal { .. } => assert!(false),
    ///     DestType::Drop => assert!(false),
    ///     DestType::External { external_src_addr, external_src_port } => {
    ///         assert_eq!(external_src_addr, nat_ex_addr);
    ///         // Note that the NAT gave us an external port outside of its assigned port range. NATs
    ///         // from this library will do this if they are configured to do port preservation.
    ///         assert_eq!(external_src_port, client_in_port);
    ///         time += 100;
    ///         match nat.receive_external_packet(server_ex_addr, server_ex_port, external_src_addr, external_src_port, false, time) {
    ///             Some((internal_dest_addr, internal_dest_port)) => {
    ///                 assert_eq!(internal_dest_addr, client_in_addr);
    ///                 assert_eq!(internal_dest_port, client_in_port);
    ///             }
    ///             None => assert!(false),
    ///         }
    ///     }
    /// }
    ///
    /// time += timeout + 1;
    /// let translation = nat.receive_external_packet(server_ex_addr, server_ex_port, nat_ex_addr, client_in_port, false, time);
    /// assert!(translation.is_none());
    /// ```
    pub const EASY_NAT: u32 = 0;

    /// Equivalent to: `NO_PORT_PRESERVATION`
    ///
    /// # Example
    /// ```
    /// use nat_emulation::predefines::FULL_CONE_NAT;
    /// use nat_emulation::{DestType, Nat};
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let nat_ex_addr = 11111;
    /// let mut nat = Nat::new(FULL_CONE_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);
    /// let client_in_addr = nat.assign_internal_address();
    /// let client_in_port = 17;
    /// let server_ex_addr = 22222;
    /// let server_ex_port = 80;
    ///
    /// time += 100;
    /// match nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port, time) {
    ///     DestType::Internal { .. } => assert!(false),
    ///     DestType::Drop => assert!(false),
    ///     DestType::External { external_src_addr, external_src_port } => {
    ///         assert_eq!(external_src_addr, nat_ex_addr);
    ///         // Our definition of a full cone NAT does not have port preservation.
    ///         assert!(external_src_port != client_in_port);
    ///         assert!(external_src_port >= 49152);
    ///
    ///         time += 100;
    ///         let translation = nat.receive_external_packet(server_ex_addr, server_ex_port, external_src_addr, external_src_port, false, time);
    ///         assert!(translation.is_some());
    ///     }
    /// }
    /// ```
    pub const FULL_CONE_NAT: u32 = NO_PORT_PRESERVATION;
    /// Equivalent to: `FULL_CONE_NAT | RESTRICTED_FIREWALL`
    pub const RESTRICTED_CONE_NAT: u32 = FULL_CONE_NAT | RESTRICTED_FIREWALL;
    /// Equivalent to: `FULL_CONE_NAT | PORT_RESTRICTED_FIREWALL`
    pub const PORT_RESTRICTED_CONE_NAT: u32 = FULL_CONE_NAT | PORT_RESTRICTED_FIREWALL;
    /// Equivalent to: `PORT_RESTRICTED_CONE_NAT | ADDRESS_AND_PORT_DEPENDENT_MAPPING`
    ///
    /// # Example
    /// ```
    /// use nat_emulation::predefines::SYMMETRIC_NAT;
    /// use nat_emulation::{DestType::*, Nat};
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let nat_ex_addr = 11111;
    /// let mut nat = Nat::new(SYMMETRIC_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);
    /// let client_in_addr = nat.assign_internal_address();
    /// let client_in_port = 17;
    /// let server_ex_addr = 22222;
    /// let server_ex_port0 = 80;
    /// let server_ex_port1 = 17;
    ///
    /// time += 100;
    /// let translation0 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time);
    /// let translation1 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port1, time);
    /// match (translation0, translation1) {
    ///     (
    ///         External {
    ///             external_src_addr: ex_src_addr0,
    ///             external_src_port: ex_src_port0,
    ///         },
    ///         External {
    ///             external_src_addr: ex_src_addr1,
    ///             external_src_port: ex_src_port1,
    ///         },
    ///     ) => {
    ///         assert_eq!(ex_src_addr0, nat_ex_addr);
    ///         assert_eq!(ex_src_addr1, nat_ex_addr);
    ///         assert!(ex_src_port0 != ex_src_port1);
    ///
    ///         time += 100;
    ///         let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr1, ex_src_port1, false, time);
    ///         assert!(translation.is_none());
    ///     }
    ///     _ => assert!(false),
    /// }
    /// ```
    pub const SYMMETRIC_NAT: u32 = PORT_RESTRICTED_CONE_NAT | ADDRESS_AND_PORT_DEPENDENT_MAPPING;

    /// Equivalent to: `SYMMETRIC_NAT | IP_POOLING_BEHAVIOR_ARBITRARY | INBOUND_REFRESH_BEHAVIOR_FALSE | NO_PORT_PARITY`
    /// # Example
    /// ```
    /// use nat_emulation::predefines::HARD_NAT;
    /// use nat_emulation::{DestType::*, Nat};
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let mut nat = Nat::new(HARD_NAT, [11110, 11111, 11112, 11113], 90000..=99999, 49152..=u16::MAX, rng, timeout);
    /// let client_in_addr = nat.assign_internal_address();
    /// let client_in_port = 17;
    /// let server_ex_addr = 22222;
    /// let server_ex_port0 = 80;
    /// let server_ex_port1 = 17;
    ///
    /// time += 100;
    /// let translation0 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time);
    /// let translation1 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port1, time);
    /// match (translation0, translation1) {
    ///     (
    ///         External {
    ///             external_src_addr: ex_src_addr0,
    ///             external_src_port: ex_src_port0,
    ///         },
    ///         External {
    ///             external_src_addr: ex_src_addr1,
    ///             external_src_port: ex_src_port1,
    ///         },
    ///     ) => {
    ///         // With an IP pooling behavior of "Arbitrary" we are no longer guaranteed to the
    ///         // same external IP every time.
    ///         // We could randomly get the same external IP but under this rng that doesn't happen.
    ///         assert!(ex_src_addr0 != ex_src_addr1);
    ///         // Since we have different addresses there is a miniscule chance we could randomly
    ///         // get the same port, but under this rng that doesn't happen.
    ///         assert!(ex_src_port0 != ex_src_port1);
    ///
    ///         time += 100;
    ///         let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr1, ex_src_port1, false, time);
    ///         assert!(translation.is_none());
    ///         // This hard NAT only refreshes the timeout when the client sends a packet.
    ///         time += timeout - 1;
    ///         let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr0, ex_src_port0, false, time);
    ///         assert!(translation.is_none());
    ///     }
    ///     _ => assert!(false),
    /// }
    /// ```
    pub const HARD_NAT: u32 = SYMMETRIC_NAT | IP_POOLING_BEHAVIOR_ARBITRARY | INBOUND_REFRESH_BEHAVIOR_FALSE | NO_PORT_PARITY;
    /// Equivalent to: `HARD_NAT | INTERNAL_ADDRESS_AND_PORT_HAIRPINNING | OUTBOUND_REFRESH_BEHAVIOR_FALSE | FILTERED_INBOUND_DESTROYS_MAPPING`
    /// # Example
    /// ```
    /// use nat_emulation::predefines::MISBEHAVING_NAT;
    /// use nat_emulation::{DestType, Nat};
    /// let rng = rand::rngs::mock::StepRng::new(0, 1);
    /// let mut time = 100;
    /// let timeout = 1000 * 60 * 2;
    ///
    /// let nat_ex_addr = 11111;
    /// let mut nat = Nat::new(MISBEHAVING_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);
    ///
    /// let client_in_addr = nat.assign_internal_address();
    /// let client_in_port = 17;
    /// let server_ex_addr = 22222;
    /// let server_ex_port0 = 80;
    /// let server_ex_port1 = 17;
    ///
    /// time += 100;
    /// match nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time) {
    ///     DestType::Internal { .. } => assert!(false),
    ///     DestType::Drop => assert!(false),
    ///     DestType::External { external_src_addr, external_src_port } => {
    ///         assert_eq!(external_src_addr, nat_ex_addr);
    ///
    ///         time += 100;
    ///         let translation = nat.receive_external_packet(server_ex_addr, server_ex_port1, external_src_addr, external_src_port, false, time);
    ///         assert!(translation.is_none());
    ///         // This cruel NAT deletes the server's mapping to the client because the server
    ///         // replied once on the wrong port. Some rare NATs do this!
    ///         time += 100;
    ///         let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, external_src_addr, external_src_port, false, time);
    ///         assert!(translation.is_none());
    ///     }
    /// }
    /// ```
    pub const MISBEHAVING_NAT: u32 =
        HARD_NAT | INTERNAL_ADDRESS_AND_PORT_HAIRPINNING | OUTBOUND_REFRESH_BEHAVIOR_FALSE | FILTERED_INBOUND_DESTROYS_MAPPING;
}
