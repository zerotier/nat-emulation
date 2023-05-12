mod nat_flags;
mod rng;
pub use nat_flags::{flags, predefines};
mod nat;
pub use nat::{NATRouter, DestType};


#[cfg(test)]
mod examples {
    use crate as nat_emulation;
    #[test]
    fn easy_nat_example() {
        use nat_emulation::{DestType, NATRouter};
        use nat_emulation::predefines::EASY_NAT;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = NATRouter::<EASY_NAT, 1>::new([nat_ex_addr], 90000..=99999, 49152..=u16::MAX, 12, timeout);
        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port = 80;

        time += 100;
        let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port, nat_ex_addr, client_in_port, false, time);
        assert!(reroute.is_none());

        time += 100;
        match nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port, time) {
            DestType::Internal { .. } => assert!(false),
            DestType::Drop => assert!(false),
            DestType::External { external_src_addr, external_src_port } => {
                assert_eq!(external_src_addr, nat_ex_addr);
                // Note that the NAT gave us an external port outside of its assigned port range. NATs
                // from this library will do this if they are configured to do port preservation.
                assert_eq!(external_src_port, client_in_port);
                time += 100;
                match nat.receive_external_packet(server_ex_addr, server_ex_port, external_src_addr, external_src_port, false, time) {
                    Some((internal_dest_addr, internal_dest_port)) => {
                        assert_eq!(internal_dest_addr, client_in_addr);
                        assert_eq!(internal_dest_port, client_in_port);
                    }
                    None => assert!(false),
                }
            }
        }

        time += timeout + 1;
        let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port, nat_ex_addr, client_in_port, false, time);
        assert!(reroute.is_none());
    }
    #[test]
    fn full_cone_example() {
        use nat_emulation::{DestType, NATRouter};
        use nat_emulation::predefines::FULL_CONE_NAT;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = NATRouter::<FULL_CONE_NAT, 1>::new([nat_ex_addr], 90000..=99999, 49152..=u16::MAX, 12, timeout);
        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port = 80;

        time += 100;
        match nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port, time) {
            DestType::Internal { .. } => assert!(false),
            DestType::Drop => assert!(false),
            DestType::External { external_src_addr, external_src_port } => {
                assert_eq!(external_src_addr, nat_ex_addr);
                // Our definition of a full cone NAT does not have port preservation.
                assert!(external_src_port != client_in_port);
                assert!(external_src_port >= 49152);

                time += 100;
                let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port, external_src_addr, external_src_port, false, time);
                assert!(reroute.is_some());
            }
        }
    }
    #[test]
    fn symmetric_nat_example() {
        use nat_emulation::{DestType::*, NATRouter};
        use nat_emulation::predefines::SYMMETRIC_NAT;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = NATRouter::<SYMMETRIC_NAT, 1>::new([nat_ex_addr], 90000..=99999, 49152..=u16::MAX, 12, timeout);
        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port0 = 80;
        let server_ex_port1 = 17;

        time += 100;
        let reroute0 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time);
        let reroute1 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port1, time);
        match (reroute0, reroute1) {
            (External { external_src_addr: ex_src_addr0, external_src_port: ex_src_port0 }, External { external_src_addr: ex_src_addr1, external_src_port: ex_src_port1 }) => {
                assert_eq!(ex_src_addr0, nat_ex_addr);
                assert_eq!(ex_src_addr1, nat_ex_addr);
                // These ports don't match because of Address and Port-Dependent Mapping.
                assert!(ex_src_port0 != ex_src_port1);
                // The server cannot mix and match the ports of the client when the NAT has Address
                // and Port-Dependent filtering.
                // The src and dest must be "symmetric" with what the NAT mapped.
                time += 100;
                let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr1, ex_src_port1, false, time);
                assert!(reroute.is_none());
            }
            _ => assert!(false),
        }
    }
    #[test]
    fn hard_nat_example() {
        use nat_emulation::{DestType::*, NATRouter};
        use nat_emulation::predefines::HARD_NAT;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let mut nat = NATRouter::<HARD_NAT, 4>::new([11110, 11111, 11112, 11113], 90000..=99999, 49152..=u16::MAX, 245, timeout);
        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port0 = 80;
        let server_ex_port1 = 17;

        time += 100;
        let reroute0 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time);
        let reroute1 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port1, time);
        match (reroute0, reroute1) {
            (External { external_src_addr: ex_src_addr0, external_src_port: ex_src_port0 }, External { external_src_addr: ex_src_addr1, external_src_port: ex_src_port1 }) => {
                // With an IP pooling behavior of "Arbitrary" we are no longer guaranteed to the
                // same external IP every time.
                // There is a 1/4 probability that we randomly do get the same external IP but under
                // this rng seed that doesn't happen.
                assert!(ex_src_addr0 != ex_src_addr1);
                // Since we have different addresses we could randomly get the same port but under
                // this rng seed that doesn't happen.
                assert!(ex_src_port0 != ex_src_port1);

                time += 100;
                let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr1, ex_src_port1, false, time);
                assert!(reroute.is_none());
                // A NAT wouldn't normally close this mapping yet because it received a packet
                // before the timeout. However this hard NAT only refreshes the timeout when the
                // client sends a packet.
                time += timeout - 1;
                let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr0, ex_src_port0, false, time);
                assert!(reroute.is_none());
            }
            _ => assert!(false),
        }
    }
    #[test]
    fn misbehaving_nat_example() {
        use nat_emulation::{DestType, NATRouter};
        use nat_emulation::predefines::MISBEHAVING_NAT;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = NATRouter::<MISBEHAVING_NAT, 1>::new([nat_ex_addr], 90000..=99999, 49152..=u16::MAX, 245, timeout);

        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port0 = 80;
        let server_ex_port1 = 17;

        time += 100;
        match nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time) {
            DestType::Internal { .. } => assert!(false),
            DestType::Drop => assert!(false),
            DestType::External { external_src_addr, external_src_port } => {
                assert_eq!(external_src_addr, nat_ex_addr);

                time += 100;
                let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port0, external_src_addr, external_src_port, false, time);
                assert!(reroute.is_some());
                time += 100;
                let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port1, external_src_addr, external_src_port, false, time);
                assert!(reroute.is_none());
                // This awful NAT deletes the server's mapping to the client because the server
                // replied once on the wrong port. Some rare NATs do this!
                time += 100;
                let reroute = nat.receive_external_packet(server_ex_addr, server_ex_port0, external_src_addr, external_src_port, false, time);
                assert!(reroute.is_none());
            }
        }
    }

    #[test]
    fn stateful_firewall() {
        use nat_emulation::{DestType, NATRouter};
        use nat_emulation::predefines::STATEFUL_FIREWALL;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let client_addr = 11111;
        let client_port = 17;
        let server_addr = 22222;
        let server_port = 80;
        let mut firewall = NATRouter::<STATEFUL_FIREWALL, 1>::new_no_address_translation(client_addr, 12, timeout);
        assert_eq!(firewall.assign_internal_address(), client_addr);

        time += 100;
        let reroute = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time);
        assert!(reroute.is_none());

        time += 100;
        match firewall.send_internal_packet(client_addr, client_port, server_addr, server_port, time) {
            DestType::Internal { .. } => assert!(false),
            DestType::Drop => assert!(false),
            DestType::External { external_src_addr, external_src_port } => {
                assert_eq!(external_src_addr, client_addr);
                assert_eq!(external_src_port, client_port);
            }
        }

        time += 100;
        let (internal_dest_addr, internal_dest_port) = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time).unwrap();
        assert_eq!(internal_dest_addr, client_addr);
        assert_eq!(internal_dest_port, client_port);

        time += timeout + 1;
        let reroute = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time);
        assert!(reroute.is_none());
    }

    #[test]
    fn restricted_firewall() {
        use nat_emulation::NATRouter;
        use nat_emulation::predefines::RESTRICTED_FIREWALL;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let client_addr = 11111;
        let client_port = 17;
        let server0_addr = 22222;
        let server1_addr = 33333;
        let server_port = 80;
        let mut firewall = NATRouter::<RESTRICTED_FIREWALL, 1>::new_no_address_translation(client_addr, 12, timeout);
        assert_eq!(firewall.assign_internal_address(), client_addr);

        time += 100;
        let reroute = firewall.send_internal_packet(client_addr, client_port, server0_addr, server_port, time);
        assert!(reroute.is_external());

        time += 100;
        let reroute = firewall.receive_external_packet(server1_addr, server_port, client_addr, client_port, false, time);
        assert!(reroute.is_none());
    }

    #[test]
    fn port_restricted_firewall() {
        use nat_emulation::NATRouter;
        use nat_emulation::predefines::PORT_RESTRICTED_FIREWALL;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let client_addr = 11111;
        let client_port = 2000;
        let server_addr = 22222;
        let server0_port = 80;
        let server1_port = 17;
        let mut firewall = NATRouter::<PORT_RESTRICTED_FIREWALL, 1>::new_no_address_translation(client_addr, 12, timeout);

        assert_eq!(firewall.assign_internal_address(), client_addr);

        time += 100;
        let reroute = firewall.send_internal_packet(client_addr, client_port, server_addr, server0_port, time);
        assert!(reroute.is_external());

        time += 100;
        let reroute = firewall.receive_external_packet(server_addr, server1_port, client_addr, client_port, false, time);
        assert!(reroute.is_none());
    }
}
