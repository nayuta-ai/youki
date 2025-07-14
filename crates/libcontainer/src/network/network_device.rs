use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd};

use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressScope};
use nix::sched::{setns, CloneFlags};
use oci_spec::runtime::LinuxNetDevice;

use crate::network::address::AddressClient;
use crate::network::link::LinkClient;
use crate::network::wrapper::create_network_client;
use crate::network::{NetworkError, Result};

/// Core logic for setting up addresses in the new namespace
/// This function is extracted to make it testable without system calls
pub fn setup_addresses_in_namespace(
    addrs: Vec<netlink_packet_route::address::AddressMessage>,
    new_name: &str,
    ns_index: u32,
    addr_client: &mut AddressClient,
) -> Result<()> {
    // Re-add the original IP addresses to the interface in the new namespace.
    // The kernel removes IP addresses when an interface is moved between network namespaces.
    for addr in addrs {
        tracing::debug!(
            "processing address {:?} from network device {}",
            addr.clone(),
            new_name
        );
        let mut ip_opts = None;
        let mut flags_opts = None;
        // Only move IP addresses with global scope because those are not host-specific, auto-configured,
        // or have limited network scope, making them unsuitable inside the container namespace.
        // Ref: https://www.ietf.org/rfc/rfc3549.txt
        if addr.header.scope != AddressScope::Universe {
            tracing::debug!(
                "skipping address {:?} from network device {}",
                addr.clone(),
                new_name
            );
            continue;
        }
        for attr in &addr.attributes {
            match attr {
                AddressAttribute::Flags(flags) => flags_opts = Some(*flags),
                AddressAttribute::Address(ip) => ip_opts = Some(*ip),
                _ => {}
            }
        }

        // Only move permanent IP addresses configured by the user, dynamic addresses are excluded because
        // their validity may rely on the original network namespace's context and they may have limited
        // lifetimes and are not guaranteed to be available in a new namespace.
        // Ref: https://www.ietf.org/rfc/rfc3549.txt
        if let Some(flag) = flags_opts {
            if !flag.contains(AddressFlags::Permanent) {
                tracing::debug!(
                    "skipping address {:?} from network device {}",
                    addr.clone(),
                    new_name
                );
                continue;
            }
        }
        if let Some(ip) = ip_opts {
            // Remove the interface attribute of the original address
            // to avoid issues when the interface is renamed.
            addr_client.add(ns_index, ip, addr.header.prefix_len)?;
        }
    }

    Ok(())
}

/// dev_change_netns allows to move a device given by name to a network namespace given by nsPath
/// and optionally change the device name.
/// The device name will be kept the same if device.Name is None or an empty string.
/// This function ensures that the move and rename operations occur atomically.
/// It preserves existing interface attributes, including IP addresses.
pub fn dev_change_net_namespace(
    name: String,
    netns_path: String,
    device: &LinuxNetDevice,
) -> Result<()> {
    tracing::debug!(
        "attaching network device {} to network namespace {}",
        name,
        netns_path
    );

    let mut link_client = LinkClient::new(create_network_client())?;
    let mut addr_client = AddressClient::new(create_network_client())?;

    let netns_file = File::open(netns_path)?;
    let origin_netns_file = File::open("/proc/self/ns/net")?;

    let new_name = device
        .name()
        .as_ref()
        .filter(|d| !d.is_empty())
        .map_or(name.clone(), |d| d.to_string());

    let link = link_client.get_by_name(&name)?;

    let index = link.header.index;

    // Set the interface link state to DOWN before modifying attributes like namespace or name.
    // This prevents potential conflicts or disruptions on the host network during the transition,
    // particularly if other host components depend on this specific interface or its properties.
    link_client.set_down(index)?;

    // Get the existing IP addresses on the interface.
    let addrs = addr_client.get_by_index(index)?;

    link_client.set_ns_fd(index, &new_name, netns_file.as_raw_fd())?;

    // Move the device to the new network namespace and perform necessary setup.
    // We must use a separate thread for the following reasons:
    //
    // 1. setns(2) only changes the network namespace of the calling thread, not the whole process.
    //    If we called setns in the main thread, it would affect the main thread's namespace for the rest of its lifetime,
    //    which could break other parts of the program that expect to remain in the original namespace.
    // 2. By spawning a new thread, we can safely enter the target namespace, perform the required operations (like
    //    re-adding IP addresses and bringing the interface up), and then return to the original namespace, all without
    //    affecting the main thread or the rest of the process.
    // 3. When the thread exits, its namespace context is cleaned up, ensuring that namespace changes are tightly scoped
    //    and do not leak outside the intended context.
    // 4. However, for initial setup operations like adding addresses and bringing links up, we need to execute in the
    //    main thread because these operations require CAP_NET_ADMIN capability which is typically available in the host
    //    namespace with root privileges. Without this capability, the operations would fail even if performed in the
    //    target namespace.
    //
    // This pattern is necessary for correct and safe manipulation of network namespaces in multi-threaded programs.
    let thread_handle = std::thread::spawn({
        move || -> Result<()> {
            // Enter the target network namespace for this thread only.
            setns(
                unsafe { BorrowedFd::borrow_raw(netns_file.as_raw_fd()) },
                CloneFlags::CLONE_NEWNET,
            )?;

            let mut link_client = LinkClient::new(create_network_client())?;
            let mut addr_client = AddressClient::new(create_network_client())?;

            let ns_link = link_client.get_by_name(&new_name)?;
            let ns_index = ns_link.header.index;

            setup_addresses_in_namespace(addrs, &new_name, ns_index, &mut addr_client)?;

            link_client.set_up(ns_index)?;

            // Return to the original network namespace before exiting the thread.
            setns(
                unsafe { BorrowedFd::borrow_raw(origin_netns_file.as_raw_fd()) },
                CloneFlags::CLONE_NEWNET,
            )?;
            Ok(())
        }
    });

    thread_handle
        .join()
        .map_err(|e| {
            NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Thread join error: {:?}", e),
            ))
        })?
        .map_err(|e| {
            NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Thread execution error: {:?}", e),
            ))
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netlink_packet_route::address::AddressMessage;
    use netlink_packet_route::RouteNetlinkMessage;

    use super::*;
    use crate::network::address::AddressClient;
    use crate::network::fake::FakeNetlinkClient;
    use crate::network::wrapper::ClientWrapper;

    #[test]
    fn test_setup_addresses_in_namespace() {
        let mut fake_client = FakeNetlinkClient::new();

        let mut addr_msg = AddressMessage::default();
        addr_msg.header.scope = AddressScope::Universe;
        addr_msg.header.prefix_len = 24;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));
        addr_msg
            .attributes
            .push(AddressAttribute::Flags(AddressFlags::Permanent));

        let responses = vec![RouteNetlinkMessage::NewAddress(addr_msg.clone())];
        fake_client.set_expected_responses(responses);

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();

        let addrs = vec![addr_msg];
        let result = setup_addresses_in_namespace(addrs, "eth1", 1, &mut addr_client);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let Some(send_calls) = addr_client.get_send_calls() {
            assert_eq!(send_calls.len(), 1);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_setup_addresses_in_namespace_skip_non_universe_scope() {
        let fake_client = FakeNetlinkClient::new();

        let mut addr_msg = AddressMessage::default();
        addr_msg.header.scope = AddressScope::Host; // Non-universe scope
        addr_msg.header.prefix_len = 24;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();

        let addrs = vec![addr_msg];
        let result = setup_addresses_in_namespace(addrs, "eth1", 1, &mut addr_client);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let Some(send_calls) = addr_client.get_send_calls() {
            assert_eq!(send_calls.len(), 0);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_setup_addresses_in_namespace_skip_non_permanent() {
        let mut fake_client = FakeNetlinkClient::new();

        let mut addr_msg = AddressMessage::default();
        addr_msg.header.scope = AddressScope::Universe;
        addr_msg.header.prefix_len = 24;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));
        addr_msg
            .attributes
            .push(AddressAttribute::Flags(AddressFlags::empty())); // Non-permanent

        let responses = vec![RouteNetlinkMessage::NewAddress(addr_msg.clone())];
        fake_client.set_expected_responses(responses);

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();

        let addrs = vec![addr_msg];
        let result = setup_addresses_in_namespace(addrs, "eth1", 1, &mut addr_client);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let Some(send_calls) = addr_client.get_send_calls() {
            assert_eq!(send_calls.len(), 0);
        } else {
            panic!("Expected Fake client");
        }
    }
}
