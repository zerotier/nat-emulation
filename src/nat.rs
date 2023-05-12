use std::ops::RangeInclusive;
use std::collections::HashMap;

use crate::flags::*;
use crate::rng::xorshift64star;

pub enum DestType {
    External {
        external_src_addr: u32,
        external_src_port: u16,
    },
    Internal {
        external_src_addr: u32,
        external_src_port: u16,
        internal_dest_addr: u32,
        internal_dest_port: u16,
    },
    Drop,
}
impl DestType {
    #[inline]
    pub fn is_external(&self) -> bool {
        use DestType::*;
        match self {
            External { .. } => true,
            Internal { .. } => false,
            Drop => false,
        }
    }
    #[inline]
    pub fn is_internal(&self) -> bool {
        use DestType::*;
        match self {
            External { .. } => false,
            Internal { .. } => true,
            Drop => false,
        }
    }
    #[inline]
    pub fn is_drop(&self) -> bool {
        use DestType::*;
        match self {
            External { .. } => false,
            Internal { .. } => false,
            Drop => true,
        }
    }
}

struct Entry {
    internal_addr: u32,
    internal_port: u16,
    external_port: u16,
    endpoint_addr: u32,
    endpoint_port: u16,
    last_used_time: i64,
}
pub struct NATRouter<const FLAGS: u32, const L: usize> {
    assigned_addresses: [u32; L],
    map: [Vec<Entry>; L],
    intranet: HashMap<u32, usize>,
    mapping_timeout: i64,
    max_routing_table_len: usize,
    rng: u64,
    assigned_external_ports: RangeInclusive<u16>,
    assigned_internal_addresses: RangeInclusive<u32>,
}
impl<const FLAGS: u32> NATRouter<FLAGS, 1> {
    pub fn new_no_address_translation(
        assigned_address: u32,
        rng_seed: u64,
        mapping_timeout: i64,
    ) -> Self {
        Self::new([assigned_address], assigned_address..=assigned_address, 0..=u16::MAX, rng_seed, mapping_timeout)
    }
}
impl<const FLAGS: u32, const L: usize> NATRouter<FLAGS, L> {
    pub fn new(
        assigned_external_addresses: [u32; L],
        assigned_internal_addresses: RangeInclusive<u32>,
        assigned_external_ports: RangeInclusive<u16>,
        rng_seed: u64,
        mapping_timeout: i64,
    ) -> Self {
        debug_assert!(assigned_internal_addresses.start() <= assigned_internal_addresses.end(), "The assigned_internal_addresses range must be nonempty");
        debug_assert!(assigned_external_ports.start() <= assigned_external_ports.end(), "The assigned_external_ports range must be nonempty");
        Self {
            assigned_addresses: assigned_external_addresses,
            map: std::array::from_fn(|_| Vec::new()),
            mapping_timeout,
            // We need to make sure if port_parity is on the NAT does not crash from not being able
            // to generate a unique port.
            max_routing_table_len: assigned_external_ports.len() * 2 / 5,
            rng: rng_seed,
            assigned_external_ports,
            assigned_internal_addresses,
            intranet: HashMap::new(),
        }
    }
    pub fn assigned_addresses(&self) -> &[u32; L] {
        &self.assigned_addresses
    }
    pub fn assign_internal_address(&mut self) -> u32 {
        // Instead of dealing with u32 overflow we just cast up to a u64 and sidestep the problem.
        let addr_len = *self.assigned_internal_addresses.end() as u64 - *self.assigned_internal_addresses.start() as u64 + 1;
        loop {
            let random_addr =
                (xorshift64star(&mut self.rng) % addr_len) as u32 + self.assigned_internal_addresses.start();
            if self.intranet.contains_key(&random_addr) {
                continue;
            }
            // Randomly assign this connection an external ip addr, we will only use this
            // assigned addr when IP_POOLING_BEHAVIOR_ARBITRARY is false
            self.intranet
                .insert(random_addr, xorshift64star(&mut self.rng) as usize % self.assigned_addresses.len());
            return random_addr;
        }
    }
    pub fn remove_internal_address(&mut self, internal_addr: u32) {
        self.intranet.remove(&internal_addr);
    }
    fn remap(
        &mut self,
        internal_addr: u32,
        internal_port: u16,
        external_addr: u32,
        external_port: u16,
        dest_addr: u32,
        dest_port: u16,
        current_time: i64,
    ) -> DestType {
        if let Some((dest_addr, dest_port)) = self.route_external_packet(external_addr, external_port, dest_addr, dest_port, false, current_time) {
            // Packet is for an internal recipient. We assume we are doing hairpinning because the caller has already checked `NO_HAIRPINNING`.
            if FLAGS & INTERNAL_ADDRESS_AND_PORT_HAIRPINNING > 0 {
                DestType::Internal {
                    external_src_addr: internal_addr,
                    external_src_port: internal_port,
                    internal_dest_addr: dest_addr,
                    internal_dest_port: dest_port,
                }
            } else {
                DestType::Internal {
                    external_src_addr: external_addr,
                    external_src_port: external_port,
                    internal_dest_addr: dest_addr,
                    internal_dest_port: dest_port,
                }
            }
        } else if self.assigned_addresses.contains(&dest_addr) {
            // Packet was addressed to our internal using their external addr and was filtered.
            DestType::Drop
        } else {
            DestType::External {
                external_src_addr: external_addr,
                external_src_port: external_port,
            }
        }
    }
    fn select_inet_address(&mut self, paired_addr_idx: Option<usize>, src_port: u16) -> (usize, u16) {
        if FLAGS & NO_PORT_PRESERVATION == 0 {
            let mut addr_perm: [usize; L] = std::array::from_fn(|i| i);
            let mut addr_perm_len = self.assigned_addresses.len();
            if let Some(idx) = paired_addr_idx {
                // If this NAT has the behavior of "Paired" then we may only consider
                // the paired address.
                addr_perm[0] = idx;
                addr_perm_len = 1;
            } else {
                // If this NAT has the behavior of "Arbitrary" then we want to randomly
                // choose which addr to assign to this route.
                for i in (1..addr_perm_len).rev() {
                    addr_perm.swap(i, xorshift64star(&mut self.rng) as usize % (i + 1))
                }
            }
            'next_addr: for external_address_idx in &addr_perm[..addr_perm_len] {
                for route in &self.map[*external_address_idx] {
                    if route.external_port == src_port {
                        // This addr and port combination collides so consider something else.
                        continue 'next_addr;
                    }
                }
                return (*external_address_idx, src_port);
            }
            if FLAGS & PORT_PRESERVATION_OVERLOAD > 0 {
                // src_port is currently used by all of our IP addresses, so overload that port.
                return (addr_perm[0], src_port);
            } else if FLAGS & PORT_PRESERVATION_OVERRIDE > 0 {
                let routing_table = &mut self.map[addr_perm[0]];
                for i in 0..routing_table.len() {
                    if routing_table[i].external_port == src_port {
                        // In port preservation override mode we remove everyone else who is
                        // using the chosen src_port.
                        routing_table.swap_remove(i);
                    }
                }
                return (addr_perm[0], src_port);
            }
        }
        // If we can't do any port preservation we have to randomly generate the port and address
        let mut random_addr;
        let mut random_port;
        'regen: loop {
            random_addr = paired_addr_idx.unwrap_or_else(|| xorshift64star(&mut self.rng) as usize % self.assigned_addresses.len());
            random_port = (xorshift64star(&mut self.rng) as usize % self.assigned_external_ports.len()) as u16 + self.assigned_external_ports.start();
            if FLAGS & NO_PORT_PARITY == 0 {
                // Force the port to have the same parity as the src_port.
                random_port = (random_port & !1u16) | (src_port & 1u16);
            }
            for route in &self.map[random_addr] {
                if route.external_port == random_port {
                    continue 'regen;
                }
            }
            break;
        }
        return (random_addr, random_port);
    }
    pub fn route_internal_packet(
        &mut self,
        internal_src_addr: u32,
        internal_src_port: u16,
        external_dest_addr: u32,
        external_dest_port: u16,
        current_time: i64,
    ) -> DestType {
        if self.assigned_internal_addresses.contains(&external_dest_addr) {
            return DestType::Internal {
                external_src_addr: internal_src_addr,
                external_src_port: internal_src_port,
                internal_dest_addr: external_dest_addr,
                internal_dest_port: external_dest_port,
            };
        } else if FLAGS & NO_HAIRPINNING > 0 && self.assigned_addresses.contains(&external_dest_addr) {
            return DestType::Drop;
        }
        let mut previous_mapping = if let Some(external_src_addr_idx) = self.intranet.get(&internal_src_addr) {
            if FLAGS & IP_POOLING_BEHAVIOR_ARBITRARY > 0 {
                None
            } else {
                Some((*external_src_addr_idx, None))
            }
        } else {
            return DestType::Drop;
        };

        let expiry = current_time - self.mapping_timeout;
        for address_idx in 0..self.assigned_addresses.len() {
            let routing_table = &mut self.map[address_idx];
            let mut oldest_time = i64::MAX;
            let mut oldest_idx = 0;
            let mut i = 0;
            while i < routing_table.len() {
                let route = &mut routing_table[i];
                if route.last_used_time < expiry {
                    routing_table.swap_remove(i);
                    continue;
                } else if route.internal_addr == internal_src_addr &&  route.internal_port == internal_src_port {
                    let addr_match = route.endpoint_addr == external_dest_addr;
                    let port_match = route.endpoint_port == external_dest_port;
                    let route_ex_port = route.external_port;
                    if addr_match && port_match {
                        if FLAGS & OUTBOUND_REFRESH_BEHAVIOR_FALSE == 0 {
                            route.last_used_time = current_time;
                        }
                        let route_ex_addr = self.assigned_addresses[address_idx];
                        return self.remap(
                            internal_src_addr,
                            internal_src_port,
                            route_ex_addr,
                            route_ex_port,
                            external_dest_addr,
                            external_dest_port,
                            current_time,
                        );
                    } else if (FLAGS & ADDRESS_DEPENDENT_MAPPING == 0 || addr_match) && (FLAGS & PORT_DEPENDENT_MAPPING == 0 || port_match) {
                        previous_mapping.replace((address_idx, Some(route_ex_port)));
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
        let (external_address_idx, external_port) = {
            // Attempt to reuse the previous mapping if we can.
            // This allows us to do address pairing and Endpoint-independent mapping.
            if let Some((ex_addr_idx, Some(ex_port))) = previous_mapping {
                (ex_addr_idx, ex_port)
            } else {
                self.select_inet_address(
                    previous_mapping.map(|a| a.0),
                    internal_src_port,
                )
            }
        };
        let external_addr = self.assigned_addresses[external_address_idx];
        self.map[external_address_idx].push(Entry {
            internal_addr: internal_src_addr,
            internal_port: internal_src_port,
            external_port,
            endpoint_addr: external_dest_addr,
            endpoint_port: external_dest_port,
            last_used_time: current_time,
        });
        return self.remap(
            internal_src_addr,
            internal_src_port,
            external_addr,
            external_port,
            external_dest_addr,
            external_dest_port,
            current_time,
        );
    }
    /// * `external_src_addr`:
    /// * `external_src_port`:
    /// * `external_dest_addr`:
    /// * `external_dest_port`:
    /// * `disable_filtering`: If true the NAT will disable its firewall for this one packet.
    ///    Certain NATs will read IP payloads and disable filtering if the packet is from a permitted
    ///    protocol like ICMP. It is up to the caller to emulate this behavior if they wish.
    ///
    /// Return value is `None` if the packet would be dropped by the NAT, either because there is no
    /// recipient with the specified external dest_addr and dest_port, or because the packet was
    /// actively filtered out by a firewall.
    ///
    /// Return value is `Some((internal_dest_addr, internal_dest_port))` if the packet was accepted,
    /// The caller must overwrite the `external_dest_addr` and `external_dest_port` fields of the
    /// packet with the returned `internal_dest_addr` and `internal_dest_port` values.
    pub fn route_external_packet(
        &mut self,
        external_src_addr: u32,
        external_src_port: u16,
        external_dest_addr: u32,
        external_dest_port: u16,
        disable_filtering: bool,
        current_time: i64,
    ) -> Option<(u32, u16)> {
        let mut dest_address_idx = usize::MAX;
        for i in 0..self.assigned_addresses.len() {
            if self.assigned_addresses[i] == external_dest_addr {
                dest_address_idx = i;
                break;
            }
        }
        if dest_address_idx == usize::MAX {
            // This packet was not addressed to this NAT.
            return None;
        }
        let routing_table = &mut self.map[dest_address_idx];

        let expiry = current_time - self.mapping_timeout;
        let mut needs_destruction = false;
        let mut i = 0;
        while i < routing_table.len() {
            let route = &mut routing_table[i];
            if route.last_used_time < expiry {
                routing_table.swap_remove(i);
                continue;
            } else if route.external_port == external_dest_port {
                if disable_filtering
                    || ((FLAGS & ADDRESS_DEPENDENT_FILTERING == 0 || route.endpoint_addr == external_src_addr)
                        && (FLAGS & PORT_DEPENDENT_FILTERING == 0 || route.endpoint_port == external_src_port))
                {
                    if FLAGS & INBOUND_REFRESH_BEHAVIOR_FALSE == 0 {
                        route.last_used_time = current_time;
                    }
                    return Some((route.internal_addr, route.internal_port));
                } else if FLAGS & FILTERED_INBOUND_DESTROYS_MAPPING > 0 {
                    needs_destruction = true;
                }
            }
            i += 1;
        }
        // We could not find a valid recipient or the packet was filtered.
        if needs_destruction {
            while i < routing_table.len() {
                let route = &routing_table[i];
                if route.external_port == external_dest_port {
                    routing_table.swap_remove(i);
                } else {
                    i += 1;
                }
            }
        }
        return None;
    }
}
