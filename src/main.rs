
#[test]
fn easy_nat_example() {
    use nat_emulation::{DestType, NATRouter};
    use nat_emulation::predefines::EASY_NAT;

    let mut time = 100;
    let timeout = 1000 * 60 * 2;

    let nat_ex_addr = 10;
    let mut nat = NATRouter::<EASY_NAT, 1>::new([nat_ex_addr], 100000..=200000, 3000..=u16::MAX, 12, timeout);

    let client_in_addr = nat.assign_internal_address();
    let client_in_port = 2000;
    let server_ex_addr = 10000;
    let server_ex_port = 80;

    time += 100;
    let reroute = nat.route_external_packet(server_ex_addr, server_ex_port, client_in_addr, client_in_port, false, time);
    assert!(reroute.is_none());

    time += 100;
    match nat.route_internal_packet(client_in_addr, client_in_port, server_ex_addr, server_ex_port, time) {
        DestType::Internal { .. } => assert!(false),
        DestType::Drop => assert!(false),
        DestType::External { external_src_addr, external_src_port } => {
            time += 100;
            assert_eq!(external_src_addr, nat_ex_addr);
            // Note that the NAT gave us an external port outside of its assigned port range. NATs
            // from this library will do this if they are configured to do port preservation.
            assert_eq!(external_src_port, client_in_port);
            match nat.route_external_packet(server_ex_addr, server_ex_port, external_src_addr, external_src_port, false, time) {
                Some((internal_dest_addr, internal_dest_port)) => {
                    assert_eq!(internal_dest_addr, client_in_addr);
                    assert_eq!(internal_dest_port, client_in_port);
                }
                None => assert!(false),
            }
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
    let client_port = 2000;
    let server_addr = 22222;
    let server_port = 80;
    let mut firewall = NATRouter::<STATEFUL_FIREWALL, 1>::new_no_address_translation(client_addr, 12, timeout);

    assert_eq!(firewall.assign_internal_address(), client_addr);

    time += 100;
    let reroute = firewall.route_external_packet(server_addr, server_port, client_addr, client_port, false, time);
    assert!(reroute.is_none());

    time += 100;
    match firewall.route_internal_packet(client_addr, client_port, server_addr, server_port, time) {
        DestType::Internal { .. } => assert!(false),
        DestType::Drop => assert!(false),
        DestType::External { external_src_addr, external_src_port } => {
            assert_eq!(external_src_addr, client_addr);
            assert_eq!(external_src_port, client_port);
        }
    }

    time += 100;
    let (internal_dest_addr, internal_dest_port) = firewall.route_external_packet(server_addr, server_port, client_addr, client_port, false, time).unwrap();
    assert_eq!(internal_dest_addr, client_addr);
    assert_eq!(internal_dest_port, client_port);

    time += timeout + 1;
    let reroute = firewall.route_external_packet(server_addr, server_port, client_addr, client_port, false, time);
    assert!(reroute.is_none());
}

#[test]
fn restricted_firewall() {
    use nat_emulation::{DestType, NATRouter};
    use nat_emulation::predefines::RESTRICTED_FIREWALL;
    let mut time = 100;
    let timeout = 1000 * 60 * 2;

    let client_addr = 11111;
    let client_port = 2000;
    let server0_addr = 22222;
    let server1_addr = 33333;
    let server_port = 80;
    let mut firewall = NATRouter::<RESTRICTED_FIREWALL, 1>::new_no_address_translation(client_addr, 12, timeout);

    assert_eq!(firewall.assign_internal_address(), client_addr);

    time += 100;
    let reroute = firewall.route_external_packet(server0_addr, server_port, client_addr, client_port, false, time);
    assert!(reroute.is_none());

    time += 100;
    match firewall.route_internal_packet(client_addr, client_port, server0_addr, server_port, time) {
        DestType::Internal { .. } => assert!(false),
        DestType::Drop => assert!(false),
        DestType::External { external_src_addr, external_src_port } => {
            assert_eq!(external_src_addr, client_addr);
            assert_eq!(external_src_port, client_port);
        }
    }

    time += 100;
    let reroute = firewall.route_external_packet(server1_addr, server_port, client_addr, client_port, false, time);
    assert!(reroute.is_none());
}
