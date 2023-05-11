use std::{collections::HashMap, ops::Range};

use crate::rng::xorshift64star;

/*
 * All of the flags below conform with NAT behaviors observed by rfc4787,
 * https://datatracker.ietf.org/doc/html/rfc4787.
 *
 * By bitwise or'ing them together one can specify any combination of NAT behaviors.
 * These flags directly model NAT behaviors, however certain combinations can accurately emulate
 * common stateful firewall behaviors as well. One only needs to make sure the NAT is assigned a
 * single intranet address that matches its external address.
 *
 * A NAT with a flag set to true is at least as "hard" to punch through as a NAT with the same flag
 * set to false. In other words, the more flags set to true the more misbehaved and difficult to
 * punch through the NAT becomes.
 *
 * We also have pre-defined a set of constants for NAT types. These are combinations of flags
 * that define common NAT or firewall types one might want to replicate without having to manually
 * bitwise-or the required flags together.
 *
 */

/// https://datatracker.ietf.org/doc/html/rfc4787
/// When this is true the NAT has an "IP address pooling" behavior of "Arbitrary".
/// When this is false the NAT has an "IP address pooling" behavior of "Paired".
/// In "Paired" mode the NAT will always assign the same internal intranet address to the same
/// external internet address.
/// In "Arbitrary" mode the NAT will randomly assign an external internet address for every new
/// outbound mapping.
pub const IP_POOLING_BEHAVIOR_ARBITRARY: u32 = 1 << 0;

pub const ADDRESS_DEPENDENT_MAPPING: u32 = 1 << 1;
pub const PORT_DEPENDENT_MAPPING: u32 = 1 << 2;
pub const ADDRESS_AND_PORT_DEPENDENT_MAPPING: u32 = ADDRESS_DEPENDENT_MAPPING | PORT_DEPENDENT_MAPPING;

pub const ADDRESS_DEPENDENT_FILTERING: u32 = 1 << 3;
pub const PORT_DEPENDENT_FILTERING: u32 = 1 << 4;
pub const ADDRESS_AND_PORT_DEPENDENT_FILTERING: u32 = ADDRESS_DEPENDENT_FILTERING | PORT_DEPENDENT_FILTERING;

/// If true, the NAT will not attempt to hairpin intranet to intranet packets and instead drop them.
/// By default the NAT will always hairpin intranet to intranet packets, rewriting the src_address and
/// src_port to be the external internet address and port of the sender.
pub const NO_HAIRPINNING: u32 = 1 << 5;
/// If true, the NAT will attempt to hairpin intranet to intranet packets, but it will rewrite the
/// src_address and src_port to be the internal intranet address and port of the sender.
/// This flag has no effect if `NO_HAIRPINNING` is true.
pub const INTERNAL_ADDRESS_AND_PORT_HAIRPINNING: u32 = 1 << 6;

/// If true, the NAT will not refresh the timeout on a mapping that just received an inbound packet.
pub const INBOUND_REFRESH_BEHAVIOR_FALSE: u32 = 1 << 8;
/// If true, the NAT will not refresh the timeout on a mapping that just sent an outbound packet.
pub const OUTBOUND_REFRESH_BEHAVIOR_FALSE: u32 = 1 << 7;
/// If true, if an inbound packet is filtered by the NAT, the NAT will also destroy any mappings
/// connected to the dest_address and dest_port specified by the inbound packet.
pub const FILTERED_INBOUND_DESTROYS_MAPPING: u32 = 1 << 9;

/// If true, the NAT will make no attempt to preserve the source port number of a outbound packet.
/// For all outbound connections, intranet ports will be mapped to a random external port.
pub const NO_PORT_PRESERVATION: u32 = 1 << 10;
/// If true, the NAT will make no attempt to preserve parity of the source port number of an
/// outbound packet. Preserving port parity can help some protocols, as described in rfc4787.
pub const NO_PORT_PARITY: u32 = 1 << 11;
/// If true, the NAT will force source port preservation by overwritting older mappings that are
/// using the same combination of external address and source port as the newer mapping.
/// This flag has no effect if `NO_PORT_PRESERVATION` is true.
pub const PORT_PRESERVATION_OVERRIDE: u32 = 1 << 12;
/// If true, the NAT will force source port preservation by allowing multiple intranet addresses to
/// share a single port number.
/// When an inbound packet is addressed to an overloaded port it is nondeterministic which intranet
/// address will be sent this packet. If address or port filtering are on the NAT will send the
/// packet to some intranet address that match the filtering.
/// This flag has no effect if `NO_PORT_PRESERVATION` is true.
pub const PORT_PRESERVATION_OVERLOAD: u32 = 1 << 13;

/* Beginning of pre-defined NAT types */

pub const STATEFUL_FIREWALL: u32 = PORT_PRESERVATION_OVERRIDE;
pub const RESTRICTED_FIREWALL: u32 = STATEFUL_FIREWALL | ADDRESS_DEPENDENT_FILTERING;
pub const PORT_RESTRICTED_FIREWALL: u32 = STATEFUL_FIREWALL | ADDRESS_AND_PORT_DEPENDENT_FILTERING;
pub const MISBEHAVING_FIREWALL: u32 = PORT_RESTRICTED_FIREWALL | PORT_PRESERVATION_OVERLOAD;

pub const EASY_NAT: u32 = 0;

pub const FULL_CONE_NAT: u32 = NO_PORT_PRESERVATION;
pub const RESTRICTED_CONE_NAT: u32 = FULL_CONE_NAT | RESTRICTED_FIREWALL;
pub const PORT_RESTRICTED_CONE_NAT: u32 = FULL_CONE_NAT | PORT_RESTRICTED_FIREWALL;
pub const SYMMETRIC_NAT: u32 = PORT_RESTRICTED_CONE_NAT | ADDRESS_AND_PORT_DEPENDENT_MAPPING;

pub const HARD_NAT: u32 = SYMMETRIC_NAT | IP_POOLING_BEHAVIOR_ARBITRARY | INBOUND_REFRESH_BEHAVIOR_FALSE | NO_PORT_PARITY;
pub const MISBEHAVING_NAT: u32 =
    HARD_NAT | INTERNAL_ADDRESS_AND_PORT_HAIRPINNING | OUTBOUND_REFRESH_BEHAVIOR_FALSE | FILTERED_INBOUND_DESTROYS_MAPPING;

pub enum DestType {
    Internet {
        src_address: u32,
        src_port: u16,
        dest_address: u32,
        dest_port: u16,
    },
    Intranet {
        src_address: u32,
        src_port: u16,
        dest_address: u32,
        dest_port: u16,
    },
    Drop,
}
impl DestType {
    pub fn unwrap(&self) -> Option<(u32, u16, u32, u16)> {
        match self {
            DestType::Internet { src_address, src_port, dest_address, dest_port }
            | DestType::Intranet { src_address, src_port, dest_address, dest_port } => Some((*src_address, *src_port, *dest_address, *dest_port)),
            DestType::Drop => None,
        }
    }
}

struct Entry {
    intranet_address: u32,
    intranet_port: u16,
    internet_port: u16,
    /// When `ADDRESS_DEPENDENT_MAPPING` is false this will be set to the very last `dest_address`
    /// sent through this mapping. This means `ADDRESS_DEPENDENT_FILTERING == true` will require that port
    /// on future inbound packets.
    endpoint_address: u32,
    /// When `PORT_DEPENDENT_MAPPING` is false this will be set to the very last `dest_port`
    /// sent through this mapping. This means `PORT_DEPENDENT_FILTERING == true` will require that port
    /// on future inbound packets.
    endpoint_port: u16,
    last_used_time: i64,
}
pub const IP_POOLING_MAXIMUM: usize = 64;
pub struct NAT {
    addresses_len: usize,
    assigned_addresses: [u32; IP_POOLING_MAXIMUM],
    map: [Vec<Entry>; IP_POOLING_MAXIMUM],
    intranet: HashMap<u32, usize>,
    mapping_timeout: i64,
    max_routing_table_len: usize,
    rng: u64,
    valid_internet_ports: Range<u16>,
    valid_intranet_addresses: Range<u32>,
    flags: u32,
}
impl NAT {
    pub fn new(
        assigned_internet_addresses: &[u32],
        assigned_intranet_addresses: Range<u32>,
        assigned_internet_ports: Range<u16>,
        rng_seed: u64,
        mapping_timeout: i64,
        flags: u32,
    ) -> Self {
        let mut addresses = [0u32; IP_POOLING_MAXIMUM];
        addresses[..assigned_internet_addresses.len()].copy_from_slice(assigned_internet_addresses);
        Self {
            addresses_len: assigned_internet_addresses.len(),
            assigned_addresses: addresses,
            map: std::array::from_fn(|_| Vec::new()),
            mapping_timeout,
            // We need to make sure if port_parity is on the NAT does not crash from not being able
            // to generate a unique port.
            max_routing_table_len: assigned_internet_ports.len() * 2 / 5,
            rng: rng_seed,
            valid_internet_ports: assigned_internet_ports,
            valid_intranet_addresses: assigned_intranet_addresses,
            flags,
            intranet: HashMap::new(),
        }
    }
    pub fn assigned_addresses(&self) -> &[u32] {
        &self.assigned_addresses[..self.addresses_len]
    }
    pub fn assign_intranet_address(&mut self) -> u32 {
        loop {
            let random_address =
                (xorshift64star(&mut self.rng) as usize % self.valid_intranet_addresses.len()) as u32 + self.valid_intranet_addresses.start;
            if self.intranet.contains_key(&random_address) {
                continue;
            }
            // Randomly assign this connection an external ip address, we will only use this
            // assigned address when IP_POOLING_BEHAVIOR_ARBITRARY is false
            self.intranet
                .insert(random_address, xorshift64star(&mut self.rng) as usize % self.addresses_len);
            return random_address;
        }
    }
    pub fn remove_intranet_address(&mut self, intranet_address: u32) {
        self.intranet.remove(&intranet_address);
    }
    fn remap(
        &mut self,
        intranet_address: u32,
        intranet_port: u16,
        internet_address: u32,
        internet_port: u16,
        dest_address: u32,
        dest_port: u16,
        current_time: i64,
    ) -> DestType {
        if let Some((_, _, dest_address, dest_port)) =
            self.from_internet(internet_address, internet_port, dest_address, dest_port, false, current_time)
        {
            // Packet is for an internal recipient. We assume we are doing hairpinning to rewrite the packet for our intranet.
            if self.flags & INTERNAL_ADDRESS_AND_PORT_HAIRPINNING > 0 {
                DestType::Intranet {
                    src_address: intranet_address,
                    src_port: intranet_port,
                    dest_address,
                    dest_port,
                }
            } else {
                DestType::Intranet {
                    src_address: internet_address,
                    src_port: internet_port,
                    dest_address,
                    dest_port,
                }
            }
        } else if self.assigned_addresses.contains(&dest_address) {
            // Packet was addressed to our intranet using their external address and was filtered.
            DestType::Drop
        } else {
            DestType::Internet {
                src_address: internet_address,
                src_port: internet_port,
                dest_address,
                dest_port,
            }
        }
    }
    fn select_inet_address(&mut self, paired_address_idx: Option<usize>, src_port: u16) -> (usize, u16) {
        if self.flags & NO_PORT_PRESERVATION == 0 {
            let mut addr_perm: [usize; IP_POOLING_MAXIMUM] = std::array::from_fn(|i| i);
            let mut addr_perm_len = self.addresses_len;
            if let Some(idx) = paired_address_idx {
                // If this NAT has the behavior of "Paired" then we may only consider
                // the paired address.
                addr_perm[0] = idx;
                addr_perm_len = 1;
            } else {
                // If this NAT has the behavior of "Arbitrary" then we want to randomly
                // choose which address to assign to this route.
                for i in (1..addr_perm_len).rev() {
                    addr_perm.swap(i, xorshift64star(&mut self.rng) as usize % (i + 1))
                }
            }
            'next_addr: for internet_address_idx in &addr_perm[..addr_perm_len] {
                for route in &self.map[*internet_address_idx] {
                    if route.internet_port == src_port {
                        // This address and port combination collides so consider something else.
                        continue 'next_addr;
                    }
                }
                return (*internet_address_idx, src_port);
            }
            if self.flags & PORT_PRESERVATION_OVERLOAD > 0 {
                // src_port is currently used by all of our IP addresses, so overload that port.
                return (addr_perm[0], src_port);
            } else if self.flags & PORT_PRESERVATION_OVERRIDE > 0 {
                let routing_table = &mut self.map[addr_perm[0]];
                for i in 0..routing_table.len() {
                    if routing_table[i].internet_port == src_port {
                        // In port preservation override mode we remove everyone else who is
                        // using the chosen src_port.
                        routing_table.swap_remove(i);
                    }
                }
                return (addr_perm[0], src_port);
            }
        }
        // If we can't do any port preservation we have to randomly generate the port and address
        let mut random_address;
        let mut random_port;
        'regen: loop {
            random_address = paired_address_idx.unwrap_or_else(|| xorshift64star(&mut self.rng) as usize % self.addresses_len);
            random_port = (xorshift64star(&mut self.rng) as usize % self.valid_internet_ports.len()) as u16 + self.valid_internet_ports.start;
            if self.flags & NO_PORT_PARITY == 0 {
                // Force the port to have the same parity as the src_port.
                random_port = (random_port & !1u16) | (src_port & 1u16);
            }
            for route in &self.map[random_address] {
                if route.internet_port == random_port {
                    continue 'regen;
                }
            }
            break;
        }
        return (random_address, random_port);
    }
    pub fn from_intranet(&mut self, src_address: u32, src_port: u16, dest_address: u32, dest_port: u16, current_time: i64) -> DestType {
        if self.valid_intranet_addresses.contains(&dest_address) {
            return DestType::Intranet { src_address, src_port, dest_address, dest_port };
        } else if self.flags & NO_HAIRPINNING > 0 && self.assigned_addresses.contains(&dest_address) {
            return DestType::Drop;
        }
        let assigned_address_idx = self.intranet.get(&src_address);
        if assigned_address_idx.is_none() {
            return DestType::Drop;
        }

        let expiry = current_time - self.mapping_timeout;
        for address_idx in 0..self.addresses_len {
            let routing_table = &mut self.map[address_idx];
            let mut oldest_time = i64::MAX;
            let mut oldest_idx = 0;
            let mut i = 0;
            while i < routing_table.len() {
                let route = &mut routing_table[i];
                if route.last_used_time < expiry {
                    routing_table.swap_remove(i);
                    continue;
                } else if route.intranet_address == src_address {
                    if route.intranet_port == src_port {
                        if (self.flags & ADDRESS_DEPENDENT_MAPPING == 0 || route.endpoint_address == dest_address)
                            && (self.flags & PORT_DEPENDENT_MAPPING == 0 || route.endpoint_port == dest_port)
                        {
                            route.endpoint_address = dest_address;
                            route.endpoint_port = dest_port;
                            if self.flags & OUTBOUND_REFRESH_BEHAVIOR_FALSE == 0 {
                                route.last_used_time = current_time;
                            }
                            let internet_address = self.assigned_addresses[i];
                            let internet_port = route.internet_port;
                            return self.remap(
                                src_address,
                                src_port,
                                internet_address,
                                internet_port,
                                dest_address,
                                dest_port,
                                current_time,
                            );
                        }
                    }
                }
                if oldest_time >= route.last_used_time {
                    oldest_time = route.last_used_time;
                    oldest_idx = i;
                }
                i += 1;
            }
            if routing_table.len() >= self.max_routing_table_len {
                routing_table.swap_remove(oldest_idx);
            }
        }

        let (internet_address_idx, internet_port) = self.select_inet_address(
            if self.flags & IP_POOLING_BEHAVIOR_ARBITRARY > 0 {
                None
            } else {
                assigned_address_idx.cloned()
            },
            src_port,
        );
        let internet_address = self.assigned_addresses[internet_address_idx];
        self.map[internet_address_idx].push(Entry {
            intranet_address: src_address,
            intranet_port: src_port,
            internet_port,
            endpoint_address: dest_address,
            endpoint_port: dest_port,
            last_used_time: current_time,
        });
        return self.remap(
            src_address,
            src_port,
            internet_address,
            internet_port,
            dest_address,
            dest_port,
            current_time,
        );
    }
    pub fn from_internet(
        &mut self,
        src_address: u32,
        src_port: u16,
        dest_address: u32,
        dest_port: u16,
        disable_filtering: bool,
        current_time: i64,
    ) -> Option<(u32, u16, u32, u16)> {
        let mut dest_address_idx = IP_POOLING_MAXIMUM;
        for i in 0..self.addresses_len {
            if self.assigned_addresses[i] == dest_address {
                dest_address_idx = i;
                break;
            }
        }
        if dest_address_idx == IP_POOLING_MAXIMUM {
            // This packet was not addressed to this router/NAT
            return None;
        }
        let routing_table = &mut self.map[dest_address_idx];

        let expiry = current_time - self.mapping_timeout;
        let mut needs_destruction = false;
        let mut i = 0;
        while i < routing_table.len() {
            let route = &mut routing_table[dest_address_idx];
            if route.last_used_time < expiry {
                routing_table.swap_remove(i);
            } else if route.internet_port == dest_port {
                if disable_filtering
                    || ((self.flags & ADDRESS_DEPENDENT_FILTERING == 0 || route.endpoint_address == src_address)
                        && (self.flags & PORT_DEPENDENT_FILTERING == 0 || route.endpoint_port == src_port))
                {
                    if self.flags & INBOUND_REFRESH_BEHAVIOR_FALSE == 0 {
                        route.last_used_time = current_time;
                    }
                    return Some((src_address, src_port, route.intranet_address, route.intranet_port));
                } else if self.flags & FILTERED_INBOUND_DESTROYS_MAPPING > 0 {
                    needs_destruction = true;
                }
            } else {
                i += 1;
            }
        }
        // We could not find a valid recipient or the packet was filtered.
        if needs_destruction {
            while i < routing_table.len() {
                let route = &routing_table[i];
                if route.internet_port == dest_port {
                    routing_table.swap_remove(i);
                } else {
                    i += 1;
                }
            }
        }
        return None;
    }
}
