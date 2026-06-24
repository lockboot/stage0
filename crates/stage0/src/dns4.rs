// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hostname resolution over UDP.
//!
//! Metadata is reached at fixed link-local IPs, but a payload URL may name a host
//! (e.g. an S3/GCS bucket). The HTTP client (`http.rs`) calls [`resolve`] for any
//! non-literal host, turning it into an IPv4 address before the TCP connect.
//!
//! We do NOT use `EFI_DNS4`. EC2's UEFI firmware ships none of it (its OVMF build
//! gates DnsDxe behind the HTTP-boot flags, which default off), and `EFI_DNS4` is in
//! any case redundant with `EFI_UDP4`, which is always present where DHCP works (DHCP
//! is built on it). So we resolve names directly: build a DNS A-record query, send it
//! over UDP (see `udp4.rs`) to each DHCP-provided resolver, parse the answer.
//!
//! DNS integrity is not a trust boundary here: a spoofed answer only yields an IP
//! whose payload must still pass the sha256/ed25519 admission check, or stage0
//! fail-closes. So the parser only has to be robust against malformed input, not
//! authenticated. Every offset below is bounds-checked accordingly.

use alloc::vec::Vec;

use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::Status;
use uefi_raw::protocol::network::ip4_config2::Ip4Config2DataType;
use uefi_raw::Ipv4Address;

const DNS_PORT: u16 = 53;
/// DNS is fire-and-forget over UDP: retransmit a few times, short wait each.
const DNS_TRIES: u32 = 3;
const DNS_TRY_MS: u64 = 2_000;

/// Resolve a non-literal `host` to an IPv4 address using the DHCP-provided DNS servers
/// over UDP, trying each server in turn (with retransmits).
pub fn resolve(host: &str) -> Result<[u8; 4], Status> {
    let servers = dns_servers().ok_or_else(|| {
        crate::slog!("stage0:   DNS: no resolver in the IPv4 lease");
        Status::NO_MAPPING
    })?;
    // 16-bit query id, varied per boot so a stale datagram can't match. Forced non-zero.
    let id = (crate::timing::since_boot_ms() as u16) | 1;
    let query = build_query(host, id)?;

    for srv in &servers {
        crate::sdbg!(
            "stage0:   DNS: asking {}.{}.{}.{} for {host}",
            srv.0[0], srv.0[1], srv.0[2], srv.0[3]
        );
        let resp = match crate::udp4::query(srv.0, DNS_PORT, &query, DNS_TRIES, DNS_TRY_MS) {
            Ok(r) => r,
            Err(_) => continue, // resolver unreachable: try the next
        };
        if let Ok(ip) = parse_response(&resp, id) {
            crate::sdbg!(
                "stage0:   resolved {host} -> {}.{}.{}.{}",
                ip[0], ip[1], ip[2], ip[3]
            );
            return Ok(ip);
        }
    }
    crate::slog!("stage0:   DNS: no answer for {host}");
    Err(Status::NOT_FOUND)
}

/// Build a DNS query for the A record of `host`: 12-byte header (recursion desired, one
/// question) then the encoded name and QTYPE=A / QCLASS=IN.
fn build_query(host: &str, id: u16) -> Result<Vec<u8>, Status> {
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: recursion desired
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    q.extend_from_slice(&[0u8; 6]); // ANCOUNT / NSCOUNT / ARCOUNT
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(Status::INVALID_PARAMETER);
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(q)
}

/// Parse a DNS response and return the first A record. Name-compression pointers are
/// skipped, not followed (we never need a name's contents). Defensive on every offset.
fn parse_response(msg: &[u8], id: u16) -> Result<[u8; 4], Status> {
    let be16 = |o: usize| ((msg[o] as u16) << 8) | msg[o + 1] as u16;
    if msg.len() < 12 || be16(0) != id {
        return Err(Status::PROTOCOL_ERROR);
    }
    if be16(2) & 0x000f != 0 {
        return Err(Status::NOT_FOUND); // non-zero RCODE (NXDOMAIN, SERVFAIL, ...)
    }
    let qd = be16(4);
    let an = be16(6);
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4).ok_or(Status::PROTOCOL_ERROR)?; // QTYPE + QCLASS
    }
    for _ in 0..an {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            return Err(Status::PROTOCOL_ERROR);
        }
        let rtype = ((msg[pos] as u16) << 8) | msg[pos + 1] as u16;
        let rdlen = ((msg[pos + 8] as usize) << 8) | msg[pos + 9] as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return Err(Status::PROTOCOL_ERROR);
        }
        if rtype == 1 && rdlen == 4 {
            return Ok([msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]]);
        }
        pos += rdlen;
    }
    Err(Status::NOT_FOUND)
}

/// Advance past a DNS name, returning the offset just after it. A compression pointer
/// (top two bits set) ends the name in two bytes; we stop there rather than follow it.
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, Status> {
    loop {
        let len = *msg.get(pos).ok_or(Status::PROTOCOL_ERROR)?;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            return pos.checked_add(2).filter(|&p| p <= msg.len()).ok_or(Status::PROTOCOL_ERROR);
        }
        pos = pos
            .checked_add(1 + len as usize)
            .filter(|&p| p <= msg.len())
            .ok_or(Status::PROTOCOL_ERROR)?;
    }
}

/// The DHCP-provided resolver list from `EFI_IP4_CONFIG2`. `None` if the interface is
/// unaddressed or advertises no DNS server.
fn dns_servers() -> Option<Vec<Ipv4Address>> {
    let handle = boot::get_handle_for_protocol::<Ip4Config2>().ok()?;
    let mut ip4 = Ip4Config2::new(handle).ok()?;
    let info = ip4.get_interface_info().ok()?;
    if info.station_addr.0 == [0, 0, 0, 0] {
        return None;
    }
    // DNS_SERVER data is a packed array of EFI_IPv4_ADDRESS (4 bytes each).
    let servers: Vec<Ipv4Address> = ip4
        .get_data(Ip4Config2DataType::DNS_SERVER)
        .ok()?
        .chunks_exact(4)
        .map(|c| Ipv4Address([c[0], c[1], c[2], c[3]]))
        .collect();
    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}
