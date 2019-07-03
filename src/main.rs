use std::net::UdpSocket;
use std::fs;
use ron;
use serde::Deserialize;
use std::collections::HashMap;
use dnsrelay::*;
use std::net::SocketAddr;

#[derive(Deserialize, Debug)]
struct Hosts {
    records: HashMap<String, String>
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:53")?;
    let server = ("8.8.8.8", 53);
    let file = fs::read_to_string("dnsrelay.ron")?;
    let _hosts: Hosts = ron::de::from_str(&file).unwrap();
    let hosts: HashMap<String, String> = _hosts.records;
    let mut transactions: HashMap<u16, SocketAddr> = HashMap::new();
    loop {
        let mut buffer = BytePacketBuffer::new();
        let (_, src) = socket.recv_from(&mut buffer.buf)?;
        let mut packet = DnsPacket::from_buffer(&mut buffer)?;
        let ip = src.ip().to_string();
        if ip == "127.0.0.1" {
            match hosts.get(&packet.questions[0].qname) {
                Some(ip) => {
                    packet.header.qr = true;
                    packet.header.opcode = 0;
                    packet.header.aa = false;
                    packet.header.tc = false;
                    packet.header.rd = true;
                    packet.header.ra = true;
                    packet.header.z = (false, false, false);
                    packet.header.rcode = match ip.as_str() {
                        "0.0.0.0" => RCode::NXDOMAIN,
                        _ => RCode::NOERROR
                    };
                    packet.answers.push(DnsRecord::A {
                        domain: packet.questions[0].qname.clone(),
                        addr: ip.parse().unwrap(),
                        ttl: 299
                    });
                    packet.header.ancount = 1;
                    packet.resources.clear();
                    packet.header.arcount = 0;
                    let mut res_buf = BytePacketBuffer::new();
                    packet.write(&mut res_buf).unwrap();
                    socket.send_to(&res_buf.buf, src)?;
                }
                None => {
                    &mut transactions.insert(packet.header.id, src.clone());
                    socket.send_to(&buffer.buf, server)?;
                }
            }
        } else {
            let serv = (&mut transactions).get(&packet.header.id).unwrap();
            socket.send_to(&buffer.buf, serv)?;
        }
    }
}
