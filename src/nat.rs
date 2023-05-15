use std::collections::HashMap;
use std::ops::RangeInclusive;

use rand::RngCore;

use crate::flags::*;

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
pub struct NATRouter<R: RngCore, const M: usize> {
    external_addresses_len: usize,
    external_addresses: [u32; M],
    map: [Vec<Entry>; M],
    intranet: HashMap<u32, usize>,
    max_routing_table_len: usize,
    rng: R,
    assigned_external_ports: RangeInclusive<u16>,
    assigned_internal_addresses: RangeInclusive<u32>,
    /// This field defines the set of behaviors this NAT will exhibit.
    /// Some NATs will dynamically change their behavior during runtime in response to arbitrary
    /// triggers. This classified as a Non-deterministic NAT by rfc4787, and it is awful.
    /// If you wish to emulate such a behavior then you may mutate this field.
    pub flags: u32,
    /// This is the mapping timeout duration for this NAT, an allocated mapping from internal to
    /// external address will last for at most this long.
    /// Some NATs may dynamically change this value based on arbitrary network conditions.
    /// If you wish to emulate such a behavior then you may mutate this field.
    pub mapping_timeout: i64,
}
impl<R: RngCore> NATRouter<R, 1> {
    /// Creates a NAT object that has address translation disabled.
    /// This means the NAT will use the same single IP address accross both the internal and
    /// external network. An object created this way is no longer really a NAT, but rather a
    /// firewall. It can still translate ports however, unless you disable this behavior as well
    /// with the `PORT_PRESERVATION_OVERRIDE` flag.
    pub fn new_no_address_translation(flags: u32, assigned_address: u32, rng: R, mapping_timeout: i64) -> Self {
        Self::new(
            flags,
            [assigned_address],
            assigned_address..=assigned_address,
            0..=u16::MAX,
            rng,
            mapping_timeout,
        )
    }
}
impl<R: RngCore, const M: usize> NATRouter<R, M> {
    /// Creates a new NAT struct with a total number of external addresses that is less than the constant `M`.
    /// See `NATRouter::new` for more details.
    pub fn with_capacity(
        flags: u32,
        external_addresses: &[u32],
        internal_addresses: RangeInclusive<u32>,
        external_dynamic_ports: RangeInclusive<u16>,
        rng: R,
        mapping_timeout: i64,
    ) -> Self {
        debug_assert!(
            external_addresses.len() <= M,
            "The external_addresses array must have length less than or equal to M"
        );
        let mut external_addresses_mem = [0; M];
        external_addresses_mem[..external_addresses.len()].copy_from_slice(external_addresses);
        let mut ret = Self::new(
            flags,
            external_addresses_mem,
            internal_addresses,
            external_dynamic_ports,
            rng,
            mapping_timeout,
        );
        ret.external_addresses_len = external_addresses.len();
        ret
    }
    /// Creates a new NAT struct.
    /// * `flags`: The set of behaviors this NAT should exhibit, see module `flags`.
    /// * `external_addresses`: The list of external IP addresses the NAT is allowed to use.
    /// * `internal_addresses`: The range of internal IP addresses the NAT is allowed to
    ///   assign clients inside of its internal network.
    /// * `external_dynamic_ports`: The list of dynamic ports that the NAT is allowed to use on the
    ///   external network. The NAT may use ports outside of this range for port preservation.
    /// * `rng_seed`: Deterministic seed for the NAT's random number generator used for generating
    ///   dynamic ports, internal addresses and external addresses.
    /// * `mapping_timeout`: How long the NAT keeps an address translation mapping open for. It has
    ///   unspecified units, the caller is expected to use the same unit of time for this value as
    ///   they do for all other `current_time` timestamps in this library.
    pub fn new(
        flags: u32,
        external_addresses: [u32; M],
        internal_addresses: RangeInclusive<u32>,
        external_dynamic_ports: RangeInclusive<u16>,
        rng: R,
        mapping_timeout: i64,
    ) -> Self {
        debug_assert!(
            internal_addresses.start() <= internal_addresses.end(),
            "The internal_addresses range must be nonempty"
        );
        debug_assert!(
            external_dynamic_ports.start() <= external_dynamic_ports.end(),
            "The external_dynamic_ports range must be nonempty"
        );
        Self {
            external_addresses_len: M,
            external_addresses: external_addresses,
            map: std::array::from_fn(|_| Vec::new()),
            mapping_timeout,
            // We need to make sure if port_parity is on the NAT does not crash from not being able
            // to generate a unique port.
            max_routing_table_len: external_dynamic_ports.len() * 2 / 5,
            rng,
            assigned_external_ports: external_dynamic_ports,
            assigned_internal_addresses: internal_addresses,
            intranet: HashMap::new(),
            flags,
        }
    }
    #[inline]
    pub fn external_addresses(&self) -> &[u32] {
        &self.external_addresses[..self.external_addresses_len]
    }
    #[inline]
    pub fn internal_addresses(&self) -> &RangeInclusive<u32> {
        &self.assigned_internal_addresses
    }
    #[inline]
    pub fn external_dynamic_ports(&self) -> &RangeInclusive<u16> {
        &self.assigned_external_ports
    }
    pub fn assign_internal_address(&mut self) -> u32 {
        // Instead of dealing with u32 overflow we just cast up to a u64 and sidestep the problem.
        let addr_len = *self.assigned_internal_addresses.end() - *self.assigned_internal_addresses.start();
        loop {
            let random_addr = if addr_len == u32::MAX {
                self.rng.next_u32()
            } else {
                (self.rng.next_u32() % (addr_len + 1)) + self.assigned_internal_addresses.start()
            };
            if self.intranet.contains_key(&random_addr) {
                continue;
            }
            // Randomly assign this connection an external ip address, we will only use this
            // assigned addr when IP_POOLING_BEHAVIOR_ARBITRARY is false
            let ex_addr_idx = if M == 1 {
                0
            } else {
                (self.rng.next_u64() as usize) % self.external_addresses_len
            };
            self.intranet.insert(random_addr, ex_addr_idx);
            return random_addr;
        }
    }
    #[inline]
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
        if let Some((dest_addr, dest_port)) = self.receive_external_packet(external_addr, external_port, dest_addr, dest_port, false, current_time) {
            // Packet is for an internal recipient. We assume we are doing hairpinning because the caller has already checked `NO_HAIRPINNING`.
            if self.flags & INTERNAL_ADDRESS_AND_PORT_HAIRPINNING > 0 {
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
        } else if self.external_addresses().contains(&dest_addr) {
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
        if self.flags & NO_PORT_PRESERVATION == 0 {
            let mut addr_perm: [usize; M] = std::array::from_fn(|i| i);
            let mut addr_perm_len = self.external_addresses_len;
            if let Some(idx) = paired_addr_idx {
                // If this NAT has the behavior of "Paired" then we may only consider
                // the paired address.
                addr_perm[0] = idx;
                addr_perm_len = 1;
            } else {
                // If this NAT has the behavior of "Arbitrary" then we want to randomly
                // choose which addr to assign to this route.
                for i in (1..addr_perm_len).rev() {
                    addr_perm.swap(i, self.rng.next_u64() as usize % (i + 1))
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
            if self.flags & PORT_PRESERVATION_OVERLOAD > 0 {
                // src_port is currently used by all of our IP addresses, so overload that port.
                return (addr_perm[0], src_port);
            } else if self.flags & PORT_PRESERVATION_OVERRIDE > 0 {
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
            random_addr = paired_addr_idx.unwrap_or_else(|| {
                if M == 1 {
                    0
                } else {
                    self.rng.next_u64() as usize % self.external_addresses_len
                }
            });
            random_port = (self.rng.next_u32() % self.assigned_external_ports.len() as u32) as u16 + self.assigned_external_ports.start();
            if self.flags & NO_PORT_PARITY == 0 {
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
    /// * `internal_src_addr`: The source address of the sender on the NAT's internal network.
    /// * `internal_src_port`: The source port of the sender on the NAT's internal network.
    /// * `external_dest_addr`: The destination address of the receiver on either the internal or
    ///   external network.
    /// * `external_dest_port`: The destination port of the receiver on either the internal or the
    ///   external network.
    /// * `current_time`: A timestamp of the packet's arrival to the NAT, used to process timeouts.
    ///
    /// Return value is `DestType::Drop` if the packet would be dropped by the NAT, this happens if
    /// the packet was destined for an internal recipient that could not be routed to.
    ///
    /// Return value is `DestType::External` if the packet was accepted, and needs to be routed to a
    /// recipient on the external network, which is usually the internet. Within the packet is the
    /// translated address and port of the sender. The caller is expected to overwrite the source IP
    /// and port fields of the packet with this translated address and port.
    ///
    /// Return value is `DestType::Internal` if the packet was accepted, and needs to be routed to a
    /// recipient on the NAT's internal network. The caller is expected to overwrite the source and
    /// destination information contained in the enum onto the packet.
    pub fn send_internal_packet(
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
        } else if self.flags & NO_HAIRPINNING > 0 && self.external_addresses().contains(&external_dest_addr) {
            return DestType::Drop;
        }
        let mut previous_mapping = if let Some(external_src_addr_idx) = self.intranet.get(&internal_src_addr) {
            if self.flags & IP_POOLING_BEHAVIOR_ARBITRARY > 0 {
                None
            } else {
                Some((*external_src_addr_idx, None))
            }
        } else {
            return DestType::Drop;
        };

        let expiry = current_time - self.mapping_timeout;
        for address_idx in 0..self.external_addresses_len {
            let routing_table = &mut self.map[address_idx];
            let mut oldest_time = i64::MAX;
            let mut oldest_idx = 0;
            let mut i = 0;
            while i < routing_table.len() {
                let route = &mut routing_table[i];
                if route.last_used_time < expiry {
                    routing_table.swap_remove(i);
                    continue;
                } else if route.internal_addr == internal_src_addr && route.internal_port == internal_src_port {
                    let addr_match = route.endpoint_addr == external_dest_addr;
                    let port_match = route.endpoint_port == external_dest_port;
                    let route_ex_port = route.external_port;
                    if addr_match && port_match {
                        if self.flags & OUTBOUND_REFRESH_BEHAVIOR_FALSE == 0 {
                            route.last_used_time = current_time;
                        }
                        let route_ex_addr = self.external_addresses[address_idx];
                        return self.remap(
                            internal_src_addr,
                            internal_src_port,
                            route_ex_addr,
                            route_ex_port,
                            external_dest_addr,
                            external_dest_port,
                            current_time,
                        );
                    } else if (self.flags & ADDRESS_DEPENDENT_MAPPING == 0 || addr_match) && (self.flags & PORT_DEPENDENT_MAPPING == 0 || port_match)
                    {
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
                self.select_inet_address(previous_mapping.map(|a| a.0), internal_src_port)
            }
        };
        let external_addr = self.external_addresses[external_address_idx];
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
    /// * `external_src_addr`: The source address of the sender on the external network.
    /// * `external_src_port`: The source port of the sender on the external network.
    /// * `external_dest_addr`: The translated destination address of the receiver on the external
    ///   network.
    /// * `external_dest_port`: The translated destination port of the receiver on the external
    ///   network.
    /// * `disable_filtering`: If true the NAT will disable its firewall for this one packet.
    ///    Certain NATs will read IP payloads and disable filtering if the packet is from a
    ///    permitted protocol like ICMP. It is up to the caller to emulate this behavior if they wish.
    /// * `current_time`: A timestamp of the packet's arrival to the NAT, used to process timeouts.
    ///
    /// Return value is `None` if the packet would be dropped by the NAT, either because there is no
    /// recipient with the specified external dest_addr and dest_port, or because the packet was
    /// actively filtered out by a firewall.
    ///
    /// Return value is `Some((internal_dest_addr, internal_dest_port))` if the packet was accepted,
    /// The caller must overwrite the `external_dest_addr` and `external_dest_port` fields of the
    /// packet with the returned `internal_dest_addr` and `internal_dest_port` values.
    pub fn receive_external_packet(
        &mut self,
        external_src_addr: u32,
        external_src_port: u16,
        external_dest_addr: u32,
        external_dest_port: u16,
        disable_filtering: bool,
        current_time: i64,
    ) -> Option<(u32, u16)> {
        let mut dest_address_idx = usize::MAX;
        for i in 0..self.external_addresses_len {
            if self.external_addresses[i] == external_dest_addr {
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
                    || ((self.flags & ADDRESS_DEPENDENT_FILTERING == 0 || route.endpoint_addr == external_src_addr)
                        && (self.flags & PORT_DEPENDENT_FILTERING == 0 || route.endpoint_port == external_src_port))
                {
                    if self.flags & INBOUND_REFRESH_BEHAVIOR_FALSE == 0 {
                        route.last_used_time = current_time;
                    }
                    return Some((route.internal_addr, route.internal_port));
                } else if self.flags & FILTERED_INBOUND_DESTROYS_MAPPING > 0 {
                    needs_destruction = true;
                }
            }
            i += 1;
        }
        // We could not find a valid recipient or the packet was filtered.
        if needs_destruction {
            let mut i = 0;
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
