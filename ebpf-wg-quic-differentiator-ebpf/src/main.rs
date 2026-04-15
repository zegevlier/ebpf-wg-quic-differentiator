#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext};
use aya_log_ebpf::info;

use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

#[unsafe(no_mangle)]
static UDP_PORT_WIREGUARD: u16 = 51820;
#[unsafe(no_mangle)]
static UDP_PORT_QUIC: u16 = 443;

#[classifier]
pub fn ebpf_wg_quic_differentiator_ingress(ctx: TcContext) -> i32 {
    match unsafe { try_ebpf_wg_quic_differentiator_ingress(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

struct UdpPacketInfo {
    udp_port_wireguard: u16,
    udp_port_quic: u16,
    ip_hdr_len: usize,
    udp_hdr: UdpHdr,
}

#[inline(always)]
unsafe fn parse_udp_packet(ctx: &TcContext) -> Result<Option<UdpPacketInfo>, i32> {
    // We need to read the configured ports from the global variables
    // We need the volatile read to prevent the compiler from optimizing
    // them away, not allowing us to read the overwritten values
    // set by the loader program.
    let udp_port_wireguard = unsafe { core::ptr::read_volatile(&UDP_PORT_WIREGUARD) };
    let udp_port_quic = unsafe { core::ptr::read_volatile(&UDP_PORT_QUIC) };

    let eth_hdr = ctx.load::<EthHdr>(0).map_err(|_| 0)?;
    let ether_type = EtherType::try_from(eth_hdr.ether_type).map_err(|_| 0)?;
    let ip_hdr_offset = mem::size_of::<EthHdr>();
    let (protocol, ip_hdr_len) = match ether_type {
        EtherType::Ipv4 => {
            let ipv4_hdr = ctx.load::<Ipv4Hdr>(ip_hdr_offset).map_err(|_| 0)?;
            (ipv4_hdr.proto, ip_hdr_offset + (ipv4_hdr.ihl() as usize))
        }
        EtherType::Ipv6 => {
            let ipv6_hdr = ctx.load::<Ipv6Hdr>(ip_hdr_offset).map_err(|_| 0)?;
            (ipv6_hdr.next_hdr, ip_hdr_offset + mem::size_of::<Ipv6Hdr>())
        }
        _ => return Ok(None),
    };

    if protocol != IpProto::Udp {
        info!(
            ctx,
            "Not a UDP packet (protocol: {}), skipping", protocol as u8
        );
        return Ok(None);
    }

    let udp_hdr = ctx.load::<UdpHdr>(ip_hdr_len).map_err(|_| 0)?;

    let dest_port = udp_hdr.dst_port();
    let src_port = udp_hdr.src_port();
    info!(ctx, "UDP Packet [{}->{}]", src_port, dest_port,);

    Ok(Some(UdpPacketInfo {
        udp_port_wireguard,
        udp_port_quic,
        ip_hdr_len,
        udp_hdr,
    }))
}

unsafe fn try_ebpf_wg_quic_differentiator_ingress(mut ctx: TcContext) -> Result<i32, i32> {
    info!(
        &ctx,
        "ebpf_wg_quic_differentiator_ingress received a packet"
    );

    let info = match unsafe { parse_udp_packet(&ctx) }? {
        Some(info) => info,
        None => return Ok(0),
    };

    let dest_port = info.udp_hdr.dst_port();
    let src_port = info.udp_hdr.src_port();

    if dest_port == info.udp_port_quic {
        info!(
            &ctx,
            "Packet match QUIC/WG port: {}", info.udp_port_wireguard
        );
        // Now, we extract the first 4 bytes of the UDP payload
        // These bytes will help us differentiate WireGuard from QUIC
        // But only if we have enough data
        let payload_offset = info.ip_hdr_len + mem::size_of::<UdpHdr>();
        let payload_len = info.udp_hdr.len() as usize - mem::size_of::<UdpHdr>();
        if payload_len < 4 {
            info!(
                &ctx,
                "Not enough payload data to differentiate, treating as QUIC"
            );
            return Ok(0);
        }
        let first_4_bytes = ctx.load::<[u8; 4]>(payload_offset).map_err(|_| 0)?;

        info!(
            &ctx,
            "UDP Payload Bytes [{}->{}]: {:x} {:x} {:x} {:x}",
            src_port,
            dest_port,
            first_4_bytes[0],
            first_4_bytes[1],
            first_4_bytes[2],
            first_4_bytes[3]
        );

        // Now, we check if it matches the WireGuard header structure
        if (first_4_bytes[0] >= 0x01 && first_4_bytes[0] <= 0x04)
            && first_4_bytes[1] == 0x00
            && first_4_bytes[2] == 0x00
            && first_4_bytes[3] == 0x00
        {
            info!(
                &ctx,
                "Packet matches WireGuard header structure, treating as WireGuard"
            );
            let mut udp_hdr = info.udp_hdr;
            // We re-write the destination port to the WireGuard port, so that it gets processed by the WireGuard kernel module
            // Ensure checksum is 0 for UDP over IPv4 to let the network stack ignore it or recompute it if needed, or rely on hardware offload
            udp_hdr.set_dst_port(info.udp_port_wireguard);
            udp_hdr.check = [0, 0]; // Fix invalid checksum after rewriting port

            // We need to write back the modified UDP header to the packet
            ctx.store(info.ip_hdr_len, &udp_hdr, 0).map_err(|_| 0)?;
        } else {
            info!(
                &ctx,
                "Packet does not match WireGuard header structure, treating as QUIC"
            );
            // We don't do anything to the packet, just let it pass as QUIC
        }
    }

    Ok(0)
}

#[classifier]
pub fn ebpf_wg_quic_differentiator_egress(ctx: TcContext) -> i32 {
    match unsafe { try_ebpf_wg_quic_differentiator_egress(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ebpf_wg_quic_differentiator_egress(mut ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "ebpf_wg_quic_differentiator_egress received a packet");

    let info = match unsafe { parse_udp_packet(&ctx)? } {
        Some(info) => info,
        None => return Ok(0),
    };

    let src_port = info.udp_hdr.src_port();
    if src_port == info.udp_port_wireguard {
        // We re-write the outgoing source port to the QUIC port, so that it comes back in the ingress path with the QUIC port, allowing us to differentiate it from WireGuard responses
        info!(
            &ctx,
            "Outgoing packet from WireGuard port {}, rewriting source port to QUIC port {}",
            info.udp_port_wireguard,
            info.udp_port_quic
        );
        let mut udp_hdr = info.udp_hdr;
        udp_hdr.set_src_port(info.udp_port_quic);
        udp_hdr.check = [0, 0]; // Clear checksum so the host auto-recomputes or ignores it over veth

        // We need to write back the modified UDP header to the packet
        ctx.store(info.ip_hdr_len, &udp_hdr, 0).map_err(|_| 0)?;
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
