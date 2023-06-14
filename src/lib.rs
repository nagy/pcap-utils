use etherparse::{
    icmpv4::DestUnreachableHeader, Icmpv4Type, Icmpv6Type, InternetSlice, ReadError, SlicedPacket,
    TransportSlice,
};
use pcap::{Capture, Linktype, Offline, Packet, PacketIter};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyCapsule;
use pyo3::Python;
use std::net::SocketAddrV4;
mod tcp;

/// Represents an owned packet
#[derive(Debug, Clone, PartialEq)]
pub struct PacketOwned {
    pub time: f64,
    pub data: Vec<u8>,
}

/// Simple codec that transforms [`pcap::Packet`] into [`PacketOwned`]
pub struct Codec();

impl pcap::PacketCodec for Codec {
    type Item = PacketOwned;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        Self::Item {
            time: (packet.header.ts.tv_sec as f64) + (packet.header.ts.tv_usec as f64) / 1000000f64,
            data: (&*packet).into(),
        }
    }
}

#[pyclass]
struct MyIterator {
    iter: PacketIter<Offline, Codec>,
    linktype: Linktype,
}

#[pymethods]
impl MyIterator {
    #[new]
    fn new(input: String) -> PyResult<Self> {
        let capture = Capture::from_file(input)
            .map_err(|x| PyErr::new::<PyException, _>(format!("{}", x)))?;
        let linktype = capture.get_datalink().clone();
        Ok(Self {
            iter: capture.iter(Codec()),
            linktype: linktype,
        })
    }
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __next__<'a>(
        mut slf: PyRefMut<'a, Self>,
        py: Python<'a>,
    ) -> Option<(&'a PyBytes, f64, i32)> {
        slf.iter.next().map(|pkt| {
            let pkt = pkt.unwrap();
            (PyBytes::new(py, &pkt.data), pkt.time, slf.linktype.0)
        })
    }
}

fn try_parse(data: &[u8], linktype: Linktype) -> Result<SlicedPacket<'_>, ReadError> {
    if linktype == Linktype::IPV4 {
        SlicedPacket::from_ip(data)
    } else {
        SlicedPacket::from_ethernet(data)
    }
}

fn nth_packet_raw(input: String, nth: usize) -> Option<Vec<u8>> {
    Capture::from_file(input)
        .unwrap()
        .iter(Codec())
        .nth(nth)
        .map(|pkt| pkt.unwrap().data)
}

fn nth_packet_payload(input: String, nth: usize) -> Option<Vec<u8>> {
    nth_packet_raw(input, nth).map(|data| {
        try_parse(&data, Linktype::ETHERNET)
            .unwrap()
            .payload
            .to_owned()
    })
}

fn packet_source_socket(data: &[u8], linktype: Linktype) -> Option<std::net::SocketAddr> {
    let parsed = try_parse(data, linktype).ok()?;
    let addr: std::net::IpAddr = match parsed.ip? {
        InternetSlice::Ipv4(ref hdr, _) => hdr.source_addr().into(),
        InternetSlice::Ipv6(ref hdr, _) => hdr.source_addr().into(),
    };
    let port = match parsed.transport? {
        TransportSlice::Tcp(ref hdr) => hdr.source_port(),
        TransportSlice::Udp(ref hdr) => hdr.source_port(),
        _ => return None,
    };
    Some(std::net::SocketAddr::new(addr, port))
}

fn packet_destination_socket(data: &[u8], linktype: Linktype) -> Option<std::net::SocketAddr> {
    let parsed = try_parse(data, linktype).ok()?;
    let addr: std::net::IpAddr = match parsed.ip? {
        InternetSlice::Ipv4(ref hdr, _) => hdr.destination_addr().into(),
        InternetSlice::Ipv6(ref hdr, _) => hdr.destination_addr().into(),
    };
    let port = match parsed.transport? {
        TransportSlice::Tcp(ref hdr) => hdr.destination_port(),
        TransportSlice::Udp(ref hdr) => hdr.destination_port(),
        _ => return None,
    };
    Some(std::net::SocketAddr::new(addr, port))
}

fn packet_source_addr(data: &[u8], linktype: Linktype) -> Option<std::net::Ipv4Addr> {
    match try_parse(data, linktype).unwrap().ip {
        Some(InternetSlice::Ipv4(ref hdr, _)) => Some(hdr.source_addr()),
        Some(InternetSlice::Ipv6(ref _hdr, _)) => Default::default(),
        _ => Default::default(),
    }
}

fn packet_destination_addr(data: &[u8], linktype: Linktype) -> Option<std::net::Ipv4Addr> {
    match try_parse(data, linktype).unwrap().ip {
        Some(InternetSlice::Ipv4(ref hdr, _)) => Some(hdr.destination_addr()),
        Some(InternetSlice::Ipv6(ref _hdr, _)) => Default::default(),
        _ => Default::default(),
    }
}

fn packet_source_port(data: &[u8], linktype: Linktype) -> Option<u16> {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Tcp(ref hdr)) => Some(hdr.source_port()),
        Some(TransportSlice::Udp(ref hdr)) => Some(hdr.source_port()),
        _ => None,
    }
}

fn packet_destination_port(data: &[u8], linktype: Linktype) -> Option<u16> {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Tcp(ref hdr)) => Some(hdr.destination_port()),
        Some(TransportSlice::Udp(ref hdr)) => Some(hdr.destination_port()),
        _ => None,
    }
}

fn packet_tcp_ack(data: &[u8], linktype: Linktype) -> Option<bool> {
    match try_parse(data, linktype).ok()?.transport? {
        TransportSlice::Tcp(ref hdr) => hdr.ack().into(),
        _ => None,
    }
}

fn packet_tcp_syn(data: &[u8], linktype: Linktype) -> Option<bool> {
    match try_parse(data, linktype).ok()?.transport? {
        TransportSlice::Tcp(ref hdr) => hdr.syn().into(),
        _ => None,
    }
}

fn packet_tcp_fin(data: &[u8], linktype: Linktype) -> Option<bool> {
    match try_parse(data, linktype).ok()?.transport? {
        TransportSlice::Tcp(ref hdr) => hdr.fin().into(),
        _ => None,
    }
}

fn packet_tcp_rst(data: &[u8], linktype: Linktype) -> Option<bool> {
    match try_parse(data, linktype).ok()?.transport? {
        TransportSlice::Tcp(ref hdr) => hdr.rst().into(),
        _ => None,
    }
}

fn packet_is_tcp(data: &[u8], linktype: Linktype) -> bool {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Tcp(ref _hdr)) => true,
        _ => false,
    }
}

fn packet_is_udp(data: &[u8], linktype: Linktype) -> bool {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Udp(ref _hdr)) => true,
        _ => false,
    }
}

fn packet_is_icmp(data: &[u8], linktype: Linktype) -> bool {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Icmpv4(ref _hdr)) => true,
        Some(TransportSlice::Icmpv6(ref _hdr)) => true,
        _ => false,
    }
}

fn packet_is_icmp_echo_request(data: &[u8], linktype: Linktype) -> bool {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Icmpv4(ref hdr)) => match hdr.icmp_type() {
            Icmpv4Type::EchoRequest(_ihdr) => true,
            _ => false,
        },
        Some(TransportSlice::Icmpv6(ref hdr)) => match hdr.icmp_type() {
            Icmpv6Type::EchoRequest(_ihdr) => true,
            _ => false,
        },
        _ => false,
    }
}

fn packet_is_icmp_echo_response(data: &[u8], linktype: Linktype) -> bool {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Icmpv4(ref hdr)) => match hdr.icmp_type() {
            Icmpv4Type::EchoReply(_ihdr) => true,
            _ => false,
        },
        Some(TransportSlice::Icmpv6(ref hdr)) => match hdr.icmp_type() {
            Icmpv6Type::EchoReply(_ihdr) => true,
            _ => false,
        },
        _ => false,
    }
}

fn packet_is_icmp_destination_unreachable(data: &[u8], linktype: Linktype) -> bool {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Icmpv4(ref hdr)) => match hdr.icmp_type() {
            Icmpv4Type::DestinationUnreachable(_ihdr) => true,
            _ => false,
        },
        Some(TransportSlice::Icmpv6(ref hdr)) => match hdr.icmp_type() {
            Icmpv6Type::DestinationUnreachable(_ihdr) => true,
            _ => false,
        },
        _ => false,
    }
}

fn packet_icmp_destination_unreachable_port(data: &[u8], linktype: Linktype) -> Option<u16> {
    match try_parse(data, linktype).unwrap().transport {
        Some(TransportSlice::Icmpv4(ref hdr)) => match hdr.icmp_type() {
            Icmpv4Type::DestinationUnreachable(ihdr) => match ihdr {
                DestUnreachableHeader::Port => {
                    match SlicedPacket::from_ip(hdr.payload()).unwrap().transport {
                        Some(TransportSlice::Tcp(ref hhdr)) => Some(hhdr.destination_port()),
                        Some(TransportSlice::Udp(ref hhdr)) => Some(hhdr.destination_port()),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        },
        // TODO ipv6
        _ => None,
    }
}

/// Write out the resulting pcap file.
fn write_pcap(input: String, output: String, list_of_keep: Vec<bool>) {
    let mut cap = Capture::from_file(input).unwrap();
    let mut save = cap.savefile(output).unwrap();
    for b in list_of_keep {
        let pkt = cap.next_packet().unwrap();
        if b {
            save.write(&pkt);
        }
    }
    save.flush().unwrap();
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn pcap_utils(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<MyIterator>()?;
    #[pyfn(m)]
    fn nth_packet_raw(py: Python, input: String, nth: usize) -> Option<&PyBytes> {
        crate::nth_packet_raw(input, nth).map(|x| PyBytes::new(py, &x))
    }
    #[pyfn(m)]
    fn nth_packet_payload(py: Python, input: String, nth: usize) -> Option<&PyBytes> {
        crate::nth_packet_payload(input, nth).map(|x| PyBytes::new(py, &x))
    }
    #[pyfn(m)]
    /// Write out the resulting pcap file.
    fn write_pcap(input: String, output: String, list_of_keep: Vec<bool>) {
        crate::write_pcap(input, output, list_of_keep)
    }
    #[pyfn(m)]
    fn packet_source_socket(data: &[u8], linktype: i32) -> Option<String> {
        crate::packet_source_socket(data, Linktype(linktype)).map(|x| x.to_string())
    }
    #[pyfn(m)]
    fn packet_destination_socket(data: &[u8], linktype: i32) -> Option<String> {
        crate::packet_destination_socket(data, Linktype(linktype)).map(|x| x.to_string())
    }
    #[pyfn(m)]
    fn packet_source_port(data: &[u8], linktype: i32) -> Option<u16> {
        crate::packet_source_port(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_destination_port(data: &[u8], linktype: i32) -> Option<u16> {
        crate::packet_destination_port(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_source_addr(data: &[u8], linktype: i32) -> Option<String> {
        crate::packet_source_addr(data, Linktype(linktype)).map(|x| x.to_string())
    }
    #[pyfn(m)]
    fn packet_destination_addr(data: &[u8], linktype: i32) -> Option<String> {
        crate::packet_destination_addr(data, Linktype(linktype)).map(|x| x.to_string())
    }
    #[pyfn(m)]
    fn packet_source_addr_octets(data: &[u8], linktype: i32) -> Option<[u8; 4]> {
        crate::packet_source_addr(data, Linktype(linktype)).map(|x| x.octets())
    }
    #[pyfn(m)]
    fn packet_destination_addr_octets(data: &[u8], linktype: i32) -> Option<[u8; 4]> {
        crate::packet_destination_addr(data, Linktype(linktype)).map(|x| x.octets())
    }
    #[pyfn(m)]
    fn packet_tcp_ack(data: &[u8], linktype: i32) -> Option<bool> {
        crate::packet_tcp_ack(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_tcp_syn(data: &[u8], linktype: i32) -> Option<bool> {
        crate::packet_tcp_syn(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_tcp_fin(data: &[u8], linktype: i32) -> Option<bool> {
        crate::packet_tcp_fin(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_tcp_rst(data: &[u8], linktype: i32) -> Option<bool> {
        crate::packet_tcp_rst(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_is_tcp(data: &[u8], linktype: i32) -> bool {
        crate::packet_is_tcp(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_is_udp(data: &[u8], linktype: i32) -> bool {
        crate::packet_is_udp(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_is_icmp(data: &[u8], linktype: i32) -> bool {
        crate::packet_is_icmp(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_is_icmp_echo_request(data: &[u8], linktype: i32) -> bool {
        crate::packet_is_icmp_echo_request(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_is_icmp_echo_response(data: &[u8], linktype: i32) -> bool {
        crate::packet_is_icmp_echo_response(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_is_icmp_destination_unreachable(data: &[u8], linktype: i32) -> bool {
        crate::packet_is_icmp_destination_unreachable(data, Linktype(linktype))
    }
    #[pyfn(m)]
    fn packet_icmp_destination_unreachable_port(data: &[u8], linktype: i32) -> Option<u16> {
        crate::packet_icmp_destination_unreachable_port(data, Linktype(linktype))
    }

    use crate::tcp::*;

    #[pyfn(m)]
    fn tcp_find(
        segmenter: &PyCapsule,
        saddr: [u8; 4],
        sport: u16,
        daddr: [u8; 4],
        dport: u16,
    ) -> Option<usize> {
        use crate::tcp::*;
        let segmenter: &std::sync::Mutex<TcpSegmenter> = unsafe { segmenter.reference() };
        let segmenter = segmenter.lock().unwrap();
        segmenter.find(&TcpInfoTuple {
            ssocket: SocketAddrV4::new(saddr.into(), sport),
            dsocket: SocketAddrV4::new(daddr.into(), dport),
            syn: false,
            finrst: false,
            ack: false,
        })
    }

    #[pyfn(m)]
    fn tcp_make(py: Python) -> PyResult<&PyCapsule> {
        PyCapsule::new(
            py,
            std::sync::Mutex::new(TcpSegmenter::default()),
            std::ffi::CString::new("tcp-segmenter".to_owned())
                .unwrap()
                .into(),
        )
    }

    #[pyfn(m)]
    fn tcp_add(
        segmenter: &PyCapsule,
        saddr: [u8; 4],
        sport: u16,
        daddr: [u8; 4],
        dport: u16,
        syn: bool,
        finrst: bool,
        ack: bool,
    ) {
        let segmenter: &std::sync::Mutex<TcpSegmenter> = unsafe { segmenter.reference() };
        let mut segmenter = segmenter.lock().unwrap();
        segmenter.add(&TcpInfoTuple {
            ssocket: SocketAddrV4::new(saddr.into(), sport),
            dsocket: SocketAddrV4::new(daddr.into(), dport),
            syn,
            finrst,
            ack,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIRESHARK: &str = env!("WIRESHARK_SRC");

    #[test]
    fn parse_raw() {
        let data = &nth_packet_raw(format!("{}/test/captures/http.pcap", WIRESHARK), 0).unwrap();
        assert_eq!(data.len(), 207);
        let payload =
            &nth_packet_payload(format!("{}/test/captures/http.pcap", WIRESHARK), 0).unwrap();
        assert_eq!(payload.len(), 153);
        let sport = packet_source_port(data).unwrap();
        assert_eq!(sport, 3267);
        let dport = packet_destination_port(data).unwrap();
        assert_eq!(dport, 80);
        let saddr = packet_source_addr(data).unwrap().octets();
        assert_eq!(saddr, [10, 0, 0, 5]);
        let daddr = packet_destination_addr(data).unwrap().octets();
        assert_eq!(daddr, [207, 46, 134, 94]);

        let ssocket = packet_source_socket(data).unwrap();
        assert_eq!(ssocket, "10.0.0.5:3267".parse().unwrap());
        let dsocket = packet_destination_socket(data).unwrap();
        assert_eq!(dsocket, "207.46.134.94:80".parse().unwrap());
    }
}
