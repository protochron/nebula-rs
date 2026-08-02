//! Convenience creation of a configured Linux tun interface, returning only
//! the `OwnedFd` so the caller (running in the target netns) can hand it to
//! `Listener`. Raw ioctls keep this dependency-light; IPv4 and IPv6.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use ipnet::IpNet;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFF_UP: i16 = 0x1;
const IFF_RUNNING: i16 = 0x40;

// Linux ioctl request numbers (asm-generic/ioctls, linux/sockios.h).
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891c;
const SIOCSIFMTU: libc::c_ulong = 0x8922;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

// `struct ifreq` is 40 bytes: a 16-byte name followed by a 24-byte union.
// Rather than reproduce libc's union, three fixed 40-byte layouts cover
// every ioctl used here.
#[repr(C)]
struct IfReqShort {
    name: [libc::c_char; 16],
    data: i16,
    _pad: [u8; 22],
}
#[repr(C)]
struct IfReqSockaddr {
    name: [libc::c_char; 16],
    addr: libc::sockaddr_in,
    _pad: [u8; 8],
}
#[repr(C)]
struct IfReqInt {
    name: [libc::c_char; 16],
    val: libc::c_int,
    _pad: [u8; 20],
}
// `struct in6_ifreq` from linux/ipv6.h — the inet6 SIOCSIFADDR keys off
// ifindex rather than name.
#[repr(C)]
struct In6Ifreq {
    addr: libc::in6_addr,
    prefixlen: u32,
    ifindex: libc::c_int,
}

fn write_name(dst: &mut [libc::c_char; 16], name: &str) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() >= 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long (max 15 bytes)",
        ));
    }
    for (slot, b) in dst.iter_mut().zip(bytes) {
        *slot = *b as libc::c_char;
    }
    Ok(())
}

fn sockaddr_in_v4(addr: std::net::Ipv4Addr) -> libc::sockaddr_in {
    // s_addr is network byte order; u32::from gives host order.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from(addr).to_be(),
    };
    sa
}

pub fn create(name: &str, addr: IpNet, mtu: u32) -> io::Result<OwnedFd> {
    // Open the tun clone device and register the interface.
    let tun_raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if tun_raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let tun = unsafe { OwnedFd::from_raw_fd(tun_raw) };

    let mut ifr = IfReqShort {
        name: [0; 16],
        data: IFF_TUN | IFF_NO_PI,
        _pad: [0; 22],
    };
    write_name(&mut ifr.name, name)?;
    if unsafe { libc::ioctl(tun_raw, TUNSETIFF, &mut ifr as *mut _) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // A datagram control socket carries the address/mtu/flags ioctls. The
    // family must match the address being assigned: the kernel dispatches
    // SIOCSIFADDR to inet vs. inet6 handlers by socket family.
    let family = match addr {
        IpNet::V4(_) => libc::AF_INET,
        IpNet::V6(_) => libc::AF_INET6,
    };
    let sock_raw = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    if sock_raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock_raw) };
    let sfd = sock.as_raw_fd();

    match addr {
        IpNet::V4(v4) => {
            let mut addr_req = IfReqSockaddr {
                name: [0; 16],
                addr: sockaddr_in_v4(v4.addr()),
                _pad: [0; 8],
            };
            write_name(&mut addr_req.name, name)?;
            if unsafe { libc::ioctl(sfd, SIOCSIFADDR, &mut addr_req as *mut _) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut mask_req = IfReqSockaddr {
                name: [0; 16],
                addr: sockaddr_in_v4(v4.netmask()),
                _pad: [0; 8],
            };
            write_name(&mut mask_req.name, name)?;
            if unsafe { libc::ioctl(sfd, SIOCSIFNETMASK, &mut mask_req as *mut _) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        IpNet::V6(v6) => {
            // Disable duplicate address detection so a bind on the address
            // is possible immediately after creation instead of after the
            // tentative phase.
            std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/accept_dad"), "0")?;

            // The inet6 SIOCSIFADDR takes an in6_ifreq keyed by ifindex,
            // not name.
            let mut idx_req = IfReqInt {
                name: [0; 16],
                val: 0,
                _pad: [0; 20],
            };
            write_name(&mut idx_req.name, name)?;
            if unsafe { libc::ioctl(sfd, SIOCGIFINDEX, &mut idx_req as *mut _) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut addr_req = In6Ifreq {
                addr: libc::in6_addr {
                    s6_addr: v6.addr().octets(),
                },
                prefixlen: u32::from(v6.prefix_len()),
                ifindex: idx_req.val,
            };
            if unsafe { libc::ioctl(sfd, SIOCSIFADDR, &mut addr_req as *mut _) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    let mut mtu_req = IfReqInt {
        name: [0; 16],
        val: mtu as libc::c_int,
        _pad: [0; 20],
    };
    write_name(&mut mtu_req.name, name)?;
    if unsafe { libc::ioctl(sfd, SIOCSIFMTU, &mut mtu_req as *mut _) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // Read current flags, add UP|RUNNING, write them back.
    let mut flags_req = IfReqShort {
        name: [0; 16],
        data: 0,
        _pad: [0; 22],
    };
    write_name(&mut flags_req.name, name)?;
    if unsafe { libc::ioctl(sfd, SIOCGIFFLAGS, &mut flags_req as *mut _) } < 0 {
        return Err(io::Error::last_os_error());
    }
    flags_req.data |= IFF_UP | IFF_RUNNING;
    if unsafe { libc::ioctl(sfd, SIOCSIFFLAGS, &mut flags_req as *mut _) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(tun)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Actually creating a tun needs CAP_NET_ADMIN; run explicitly as root:
    //   sudo -E cargo test -p nebula-listener --lib tun::tests::creates_a_real_v6 -- --ignored --nocapture
    #[test]
    #[ignore]
    fn creates_a_real_v6_tun_when_privileged() {
        let fd = create("nbtest6", "fd00:9::1/64".parse().unwrap(), 1300)
            .expect("IPv6 tun creation should succeed as root");
        assert!(fd.as_raw_fd() >= 0);
    }

    #[test]
    fn rejects_overlong_interface_name() {
        let err = create(
            "this-name-is-way-too-long",
            "10.9.9.1/24".parse().unwrap(),
            1300,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // Actually creating a tun needs CAP_NET_ADMIN; run explicitly as root:
    //   sudo -E cargo test -p nebula-listener --lib tun::tests::creates -- --ignored --nocapture
    #[test]
    #[ignore]
    fn creates_a_real_tun_when_privileged() {
        let fd = create("nbtest0", "10.9.9.1/24".parse().unwrap(), 1300)
            .expect("tun creation should succeed as root");
        assert!(fd.as_raw_fd() >= 0);
    }
}
