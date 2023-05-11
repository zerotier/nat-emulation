

/// All of the flags below conform with NAT behaviors observed by rfc4787,
/// https://datatracker.ietf.org/doc/html/rfc4787.
///
/// By bitwise or'ing them together one can specify any combination of NAT behaviors.
/// These flags directly model NAT behaviors, however certain combinations can accurately emulate
/// common stateful firewall behaviors as well. One only needs to make sure the NAT is assigned a
/// single intranet address that matches its external address.
///
/// A NAT with a flag set to true is at least as "hard" to punch through as a NAT with the same flag
/// set to false. In other words, the more flags set to true the more misbehaved and difficult to
/// punch through the NAT becomes.
///
/// A `0u32` for the set of flags indicates a simple NAT that will just perform address translation
/// for outgoing and incoming packets. It will avoid translating port numbers unless there is a port
/// number collision on outgoing packets, at which point it will choose the port number for one of
/// them randomly.
///
/// A `0xffffffffu32` for the set of flags indicates the worst kind of symmetric enterprise NAT that
/// breaks nearly every requirement specified by rfc4787.
///
/// We also have a set of pre-defined flag combinations for common NAT types in the `predefines`
/// module. This module only needs to be used if you have extremely specific and uncommon NAT
/// behaviors you want to see.
pub mod flags {
    /// If true, the NAT has an "IP address pooling" behavior of "Arbitrary".
    /// By default the NAT has an "IP address pooling" behavior of "Paired".
    /// In "Paired" mode the NAT will always assign the same internal intranet address to the same
    /// external internet address.
    /// In "Arbitrary" mode the NAT will randomly assign an external internet address to every new
    /// outbound mapping.
    pub const IP_POOLING_BEHAVIOR_ARBITRARY: u32 = 1 << 0;

    /// If true, the NAT will generate an additional outbound mapping for a given src_address and
    /// src_port address whenever the dest_address does not match the previous mappings.
    pub const ADDRESS_DEPENDENT_MAPPING: u32 = 1 << 1;
    /// If true, the NAT will generate an additional outbound mapping for a given src_address and
    /// src_port address whenever the dest_port does not match the previous mappings.
    pub const PORT_DEPENDENT_MAPPING: u32 = 1 << 2;
    /// If true, the NAT will do both address and port dependent mapping.
    pub const ADDRESS_AND_PORT_DEPENDENT_MAPPING: u32 = ADDRESS_DEPENDENT_MAPPING | PORT_DEPENDENT_MAPPING;

    /// If true, the NAT will drop incoming packets that do not have the same src_address as the
    /// mapping for the given dest_address and dest_port.
    pub const ADDRESS_DEPENDENT_FILTERING: u32 = 1 << 3;
    /// If true, the NAT will drop incoming packets that do not have the same src_port as the
    /// mapping for the given dest_address and dest_port.
    pub const PORT_DEPENDENT_FILTERING: u32 = 1 << 4;
    /// If true, the NAT will do both address and port dependent filtering.
    pub const ADDRESS_AND_PORT_DEPENDENT_FILTERING: u32 = ADDRESS_DEPENDENT_FILTERING | PORT_DEPENDENT_FILTERING;

    /// If true, the NAT will not attempt to hairpin intranet to intranet packets and instead drop
    /// them.
    /// By default the NAT will always hairpin intranet to intranet packets, rewriting the
    /// src_address and src_port to be the external internet address and port of the sender.
    pub const NO_HAIRPINNING: u32 = 1 << 5;
    /// If true, the NAT will attempt to hairpin intranet to intranet packets, but it will rewrite
    /// the src_address and src_port to be the internal intranet address and port of the sender.
    /// This flag has no effect if `NO_HAIRPINNING` is true.
    pub const INTERNAL_ADDRESS_AND_PORT_HAIRPINNING: u32 = 1 << 6;

    /// If true, the NAT will not refresh the timeout on a mapping that just received an inbound
    /// packet.
    pub const INBOUND_REFRESH_BEHAVIOR_FALSE: u32 = 1 << 8;
    /// If true, the NAT will not refresh the timeout on a mapping that just sent an outbound
    /// packet.
    pub const OUTBOUND_REFRESH_BEHAVIOR_FALSE: u32 = 1 << 7;
    /// If true, if an inbound packet is filtered by the NAT, the NAT will also destroy any mappings
    /// connected to the dest_address and dest_port specified by the inbound packet.
    pub const FILTERED_INBOUND_DESTROYS_MAPPING: u32 = 1 << 9;

    /// If true, the NAT will make no attempt to preserve the source port number of a outbound
    /// packet.
    /// For all outbound connections, intranet ports will be mapped to a random external port.
    pub const NO_PORT_PRESERVATION: u32 = 1 << 10;
    /// If true, the NAT will make no attempt to preserve parity of the source port number of an
    /// outbound packet. Preserving port parity can help some protocols, as described in rfc4787.
    pub const NO_PORT_PARITY: u32 = 1 << 11;
    /// If true, the NAT will force source port preservation by overwritting older mappings that are
    /// using the same combination of external address and source port as the newer mapping.
    /// This flag has no effect if `NO_PORT_PRESERVATION` is true.
    pub const PORT_PRESERVATION_OVERRIDE: u32 = 1 << 12;
    /// If true, the NAT will force source port preservation by allowing multiple intranet addresses
    /// to share a single port number.
    /// When an inbound packet is addressed to an overloaded port it is nondeterministic which
    /// intranet address will be sent this packet. If address or port filtering are on the NAT will
    /// send the packet to some intranet address that match the filtering.
    /// This flag has no effect if `NO_PORT_PRESERVATION` is true.
    pub const PORT_PRESERVATION_OVERLOAD: u32 = 1 << 13;
}
/// This is a set of pre-defined flags for common NAT types. Each constant represents some
/// common NAT or firewall types one might want to emulate with this library. These provided for
/// convenience and are equivalent to manually bitwise-or'ing the relevant NAT flags together.
pub mod predefines {
    use super::flags::*;

    /// Equivalent to: `PORT_PRESERVATION_OVERRIDE`
    pub const STATEFUL_FIREWALL: u32 = PORT_PRESERVATION_OVERRIDE;
    /// Equivalent to: `STATEFUL_FIREWALL | ADDRESS_DEPENDENT_FILTERING`
    pub const RESTRICTED_FIREWALL: u32 = STATEFUL_FIREWALL | ADDRESS_DEPENDENT_FILTERING;
    /// Equivalent to: `STATEFUL_FIREWALL | ADDRESS_AND_PORT_DEPENDENT_FILTERING`
    pub const PORT_RESTRICTED_FIREWALL: u32 = STATEFUL_FIREWALL | ADDRESS_AND_PORT_DEPENDENT_FILTERING;
    /// Equivalent to: `PORT_RESTRICTED_FIREWALL | PORT_PRESERVATION_OVERLOAD`
    pub const MISBEHAVING_FIREWALL: u32 = PORT_RESTRICTED_FIREWALL | PORT_PRESERVATION_OVERLOAD;

    /// Equivalent to: `0`
    pub const EASY_NAT: u32 = 0;

    /// Equivalent to: `NO_PORT_PRESERVATION`
    pub const FULL_CONE_NAT: u32 = NO_PORT_PRESERVATION;
    /// Equivalent to: `FULL_CONE_NAT | RESTRICTED_FIREWALL`
    pub const RESTRICTED_CONE_NAT: u32 = FULL_CONE_NAT | RESTRICTED_FIREWALL;
    /// Equivalent to: `FULL_CONE_NAT | PORT_RESTRICTED_FIREWALL`
    pub const PORT_RESTRICTED_CONE_NAT: u32 = FULL_CONE_NAT | PORT_RESTRICTED_FIREWALL;
    /// Equivalent to: `PORT_RESTRICTED_CONE_NAT | ADDRESS_AND_PORT_DEPENDENT_MAPPING`
    pub const SYMMETRIC_NAT: u32 = PORT_RESTRICTED_CONE_NAT | ADDRESS_AND_PORT_DEPENDENT_MAPPING;

    /// Equivalent to: `SYMMETRIC_NAT | IP_POOLING_BEHAVIOR_ARBITRARY | INBOUND_REFRESH_BEHAVIOR_FALSE | NO_PORT_PARITY`
    pub const HARD_NAT: u32 = SYMMETRIC_NAT | IP_POOLING_BEHAVIOR_ARBITRARY | INBOUND_REFRESH_BEHAVIOR_FALSE | NO_PORT_PARITY;
    /// Equivalent to: `HARD_NAT | INTERNAL_ADDRESS_AND_PORT_HAIRPINNING | OUTBOUND_REFRESH_BEHAVIOR_FALSE | FILTERED_INBOUND_DESTROYS_MAPPING`
    pub const MISBEHAVING_NAT: u32 =
        HARD_NAT | INTERNAL_ADDRESS_AND_PORT_HAIRPINNING | OUTBOUND_REFRESH_BEHAVIOR_FALSE | FILTERED_INBOUND_DESTROYS_MAPPING;
}
