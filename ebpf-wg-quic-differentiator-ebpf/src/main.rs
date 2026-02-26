#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
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

#[xdp]
pub fn ebpf_wg_quic_differentiator(ctx: XdpContext) -> u32 {
    match try_ebpf_wg_quic_differentiator(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] // This function is taken directly from the aya examples
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_ebpf_wg_quic_differentiator(ctx: XdpContext) -> Result<u32, ()> {
    // We need to read the configured ports from the global variables
    // We need the volatile read to prevent the compiler from optimizing
    // them away, not allowing us to read the overwritten values
    // set by the loader program.
    let udp_port_wireguard = unsafe { core::ptr::read_volatile(&UDP_PORT_WIREGUARD) };
    let udp_port_quic = unsafe { core::ptr::read_volatile(&UDP_PORT_QUIC) };

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    // We look at both IPv4 and IPv6 packets.
    let (protocol, ip_hdr_len) = match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            (unsafe { (*ipv4hdr).proto }, Ipv4Hdr::LEN)
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            (unsafe { (*ipv6hdr).next_hdr }, Ipv6Hdr::LEN)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    match protocol {
        IpProto::Tcp => {}
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + ip_hdr_len)?;
            let dst_port = unsafe { (*udphdr).dst_port() };
            let src_port = unsafe { (*udphdr).src_port() };
            if src_port == udp_port_wireguard {
                info!(
                    &ctx,
                    "Found packet matching WG/QUIC ports ({}->{})", src_port, dst_port
                );
                // This is an outgoing WireGuard response packet, we rewrite the source port to the QUIC port
                unsafe {
                    (*udphdr.cast_mut()).set_src_port(udp_port_quic);
                }
                info!(&ctx, "Rewrote WG response packet to port {}", udp_port_quic);
            }
            if dst_port == udp_port_quic {
                info!(
                    &ctx,
                    "Found packet matching WG/QUIC ports ({}->{})", src_port, dst_port
                );
                // Now, we extract the first 4 bytes of the UDP payload
                // These bytes will help us differentiate WireGuard from QUIC
                // But only if we have enough data
                if (ctx.data_end() - ctx.data()) < (EthHdr::LEN + ip_hdr_len + UdpHdr::LEN + 4) {
                    info!(
                        &ctx,
                        "Packet too short to read UDP payload, passing through"
                    );
                    return Ok(xdp_action::XDP_PASS);
                }
                let udp_payload_offset = EthHdr::LEN + ip_hdr_len + UdpHdr::LEN;
                let udp_payload: *const [u8; 4] = ptr_at(&ctx, udp_payload_offset)?;
                let payload_bytes = unsafe { *udp_payload };
                // Print the packet content for debugging
                info!(
                    &ctx,
                    "UDP Payload Bytes [{}->{}]: {:x} {:x} {:x} {:x}",
                    src_port,
                    dst_port,
                    payload_bytes[0],
                    payload_bytes[1],
                    payload_bytes[2],
                    payload_bytes[3]
                );

                // Now, we check if it matches the WireGuard pattern
                if (payload_bytes[0] >= 0x01 && payload_bytes[0] <= 0x04)
                    && payload_bytes[1] == 0x00
                    && payload_bytes[2] == 0x00
                    && payload_bytes[3] == 0x00
                {
                    info!(&ctx, "Identified WireGuard packet based on payload pattern");
                    // This is an incoming WireGuard packet, we rewrite to the destination port to the WireGuard port
                    unsafe {
                        (*udphdr.cast_mut()).set_dst_port(udp_port_wireguard);
                    }
                    info!(&ctx, "Rewrote WG packet to port {}", udp_port_wireguard);
                } else {
                    info!(
                        &ctx,
                        "Packet does not match WireGuard payload pattern, passing through"
                    );
                }
            }
        }
        _ => {}
    };

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
