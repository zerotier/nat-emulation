mod nat_flags;
pub use nat_flags::{flags, predefines};
mod nat;
pub use nat::{DestType, Nat};

#[cfg(test)]
mod examples {
    use crate as nat_emulation;
    #[test]
    fn stateful_firewall() {
        use nat_emulation::predefines::STATEFUL_FIREWALL;
        use nat_emulation::{DestType, Nat};
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let client_addr = 11111;
        let client_port = 17;
        let server_addr = 22222;
        let server_port = 80;
        let mut firewall = Nat::no_address_translation(STATEFUL_FIREWALL, client_addr, rng, timeout);
        assert_eq!(firewall.assign_internal_address(), client_addr);

        time += 100;
        let translation = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time);
        assert!(translation.is_none());

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
        let (internal_dest_addr, internal_dest_port) = firewall
            .receive_external_packet(server_addr, server_port, client_addr, client_port, false, time)
            .unwrap();
        assert_eq!(internal_dest_addr, client_addr);
        assert_eq!(internal_dest_port, client_port);

        time += timeout + 1;
        let translation = firewall.receive_external_packet(server_addr, server_port, client_addr, client_port, false, time);
        assert!(translation.is_none());
    }

    #[test]
    fn restricted_firewall() {
        use nat_emulation::predefines::RESTRICTED_FIREWALL;
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        use nat_emulation::Nat;
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let client_addr = 11111;
        let client_port = 17;
        let server0_addr = 22222;
        let server1_addr = 33333;
        let server_port = 80;
        let mut firewall = Nat::no_address_translation(RESTRICTED_FIREWALL, client_addr, rng, timeout);
        assert_eq!(firewall.assign_internal_address(), client_addr);

        time += 100;
        let translation = firewall.send_internal_packet(client_addr, client_port, server0_addr, server_port, time);
        assert!(translation.is_external());

        time += 100;
        let translation = firewall.receive_external_packet(server1_addr, server_port, client_addr, client_port, false, time);
        assert!(translation.is_none());
    }

    #[test]
    fn port_restricted_firewall() {
        use nat_emulation::predefines::PORT_RESTRICTED_FIREWALL;
        use nat_emulation::Nat;
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let client_addr = 11111;
        let client_port = 2000;
        let server_addr = 22222;
        let server0_port = 80;
        let server1_port = 17;
        let mut firewall = Nat::no_address_translation(PORT_RESTRICTED_FIREWALL, client_addr, rng, timeout);

        assert_eq!(firewall.assign_internal_address(), client_addr);

        time += 100;
        let translation = firewall.send_internal_packet(client_addr, client_port, server_addr, server0_port, time);
        assert!(translation.is_external());

        time += 100;
        let translation = firewall.receive_external_packet(server_addr, server1_port, client_addr, client_port, false, time);
        assert!(translation.is_none());
    }
    #[test]
    fn easy_nat() {
        use nat_emulation::predefines::EASY_NAT;
        use nat_emulation::{DestType, Nat};
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = Nat::new(EASY_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);
        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port = 80;

        time += 100;
        let translation = nat.receive_external_packet(server_ex_addr, server_ex_port, nat_ex_addr, client_in_port, false, time);
        assert!(translation.is_none());

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
        let translation = nat.receive_external_packet(server_ex_addr, server_ex_port, nat_ex_addr, client_in_port, false, time);
        assert!(translation.is_none());
    }
    #[test]
    fn full_cone_nat() {
        use nat_emulation::predefines::FULL_CONE_NAT;
        use nat_emulation::{DestType, Nat};
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = Nat::new(FULL_CONE_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);
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
                let translation = nat.receive_external_packet(server_ex_addr, server_ex_port, external_src_addr, external_src_port, false, time);
                assert!(translation.is_some());
            }
        }
    }
    #[test]
    fn symmetric_nat() {
        use nat_emulation::predefines::SYMMETRIC_NAT;
        use nat_emulation::{DestType::*, Nat};
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = Nat::new(SYMMETRIC_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);
        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port0 = 80;
        let server_ex_port1 = 17;

        time += 100;
        let translation0 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time);
        let translation1 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port1, time);
        match (translation0, translation1) {
            (
                External {
                    external_src_addr: ex_src_addr0,
                    external_src_port: ex_src_port0,
                },
                External {
                    external_src_addr: ex_src_addr1,
                    external_src_port: ex_src_port1,
                },
            ) => {
                assert_eq!(ex_src_addr0, nat_ex_addr);
                assert_eq!(ex_src_addr1, nat_ex_addr);
                assert!(ex_src_port0 != ex_src_port1);

                time += 100;
                let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr1, ex_src_port1, false, time);
                assert!(translation.is_none());
            }
            _ => assert!(false),
        }
    }
    #[test]
    fn hard_nat() {
        use nat_emulation::predefines::HARD_NAT;
        use nat_emulation::{DestType::*, Nat};
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let mut nat = Nat::new(HARD_NAT, [11110, 11111, 11112, 11113], 90000..=99999, 49152..=u16::MAX, rng, timeout);
        let client_in_addr = nat.assign_internal_address();
        let client_in_port = 17;
        let server_ex_addr = 22222;
        let server_ex_port0 = 80;
        let server_ex_port1 = 17;

        time += 100;
        let translation0 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port0, time);
        let translation1 = nat.send_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port1, time);
        match (translation0, translation1) {
            (
                External {
                    external_src_addr: ex_src_addr0,
                    external_src_port: ex_src_port0,
                },
                External {
                    external_src_addr: ex_src_addr1,
                    external_src_port: ex_src_port1,
                },
            ) => {
                // With an IP pooling behavior of "Arbitrary" we are no longer guaranteed to the
                // same external IP every time.
                // We could randomly get the same external IP but under this rng that doesn't happen.
                assert!(ex_src_addr0 != ex_src_addr1);
                // Since we have different addresses there is a miniscule chance we could randomly
                // get the same port, but under this rng that doesn't happen.
                assert!(ex_src_port0 != ex_src_port1);

                time += 100;
                let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr1, ex_src_port1, false, time);
                assert!(translation.is_none());
                // This hard NAT only refreshes the timeout when the client sends a packet.
                time += timeout - 1;
                let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, ex_src_addr0, ex_src_port0, false, time);
                assert!(translation.is_none());
            }
            _ => assert!(false),
        }
    }
    #[test]
    fn misbehaving_nat() {
        use nat_emulation::predefines::MISBEHAVING_NAT;
        use nat_emulation::{DestType, Nat};
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let mut time = 100;
        let timeout = 1000 * 60 * 2;

        let nat_ex_addr = 11111;
        let mut nat = Nat::new(MISBEHAVING_NAT, [nat_ex_addr], 90000..=99999, 49152..=u16::MAX, rng, timeout);

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
                let translation = nat.receive_external_packet(server_ex_addr, server_ex_port1, external_src_addr, external_src_port, false, time);
                assert!(translation.is_none());
                // This cruel NAT deletes the server's mapping to the client because the server
                // replied once on the wrong port. Some rare NATs do this!
                time += 100;
                let translation = nat.receive_external_packet(server_ex_addr, server_ex_port0, external_src_addr, external_src_port, false, time);
                assert!(translation.is_none());
            }
        }
    }
}
