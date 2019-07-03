#[macro_use]
extern crate enum_primitive_derive;
extern crate num_traits;

use std::io::Result;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use num_traits::FromPrimitive;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize
}

impl BytePacketBuffer {

    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(&self.buf[start..start+len as usize])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) |
        (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24) |
        ((self.read()? as u32) << 16) |
        ((self.read()? as u32) << 8) |
        ((self.read()? as u32) << 0);

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;
        
        let mut delim = "";
        loop {

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {

                if !jumped {
                    self.seek(pos+2)?;
                }

                let b2 = self.get(pos+1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
            }

            else {

                pos += 1;

                if len == 0 {
                    break;
                }

                outstr.push_str(delim);

                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }
        
        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {

        let split_str = qname.split('.').collect::<Vec<&str>>();

        for label in split_str {
            let len = label.len();
            if len > 0x34 {
                return Err(Error::new(ErrorKind::InvalidInput,
                                      "Single label exceeds 63 characters of length"));
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

}

#[derive(Clone, Debug, Eq, PartialEq, Primitive)]
#[repr(u8)]
pub enum RCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: (bool, bool, bool),
    pub rcode: RCode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: (false, false, false),
            rcode: RCode::NOERROR,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0
        }
    }
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;
        
        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        
        self.rd = (a & (1 << 0)) > 0;
        self.tc = (a & (1 << 1)) > 0;
        self.aa = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.qr = (a & (1 << 7)) > 0;

        self.rcode = RCode::from_u8(b & 0x0F).unwrap();
        self.z = ((b & (1 << 6)) > 0, (b & (1 << 5)) > 0, (b & (1 << 4)) > 0);
        self.ra = (b & (1 << 7)) > 0;

        self.qdcount = buffer.read_u16()?;
        self.ancount = buffer.read_u16()?;
        self.nscount = buffer.read_u16()?;
        self.arcount = buffer.read_u16()?;
        Ok(())
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;
        
        buffer.write_u8((self.rd as u8) |
                        ((self.tc as u8) << 1) |
                        ((self.aa as u8) << 2) |
                        ((self.opcode << 3) |
                         ((self.qr as u8) << 7) as u8))?;

        buffer.write_u8((self.rcode.clone() as u8) |
                        ((self.z.2 as u8) << 4) |
                        ((self.z.1 as u8) << 5) |
                        ((self.z.0 as u8) << 6 |
                         ((self.ra as u8) << 7)))?;

        buffer.write_u16(self.qdcount)?;
        buffer.write_u16(self.ancount)?;
        buffer.write_u16(self.nscount)?;
        buffer.write_u16(self.arcount)?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum QType {
    A,
    /*
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
     */
    UNKNOWN(u16)
}

impl QType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QType::UNKNOWN(x) => x,
            QType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QType {
        match num {
            1 => QType::A,
            _ => QType::UNKNOWN(num)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: QType
}

impl DnsQuestion {
    pub fn new(qname: String, qtype: QType) -> DnsQuestion {
        DnsQuestion {qname, qtype}
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.qname)?;
        let qtype_num = (buffer.read_u16())?;
        self.qtype = QType::from_num(qtype_num);
        buffer.read_u16()?;
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.qname)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32
    }
}

impl DnsRecord {

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;
        let qtype_num = buffer.read_u16()?;
        let qtype = QType::from_num(qtype_num);
        buffer.read_u16()?; // class, which we ignore
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(((raw_addr >> 24) & 0xFF) as u8,
                                         ((raw_addr >> 16) & 0xFF) as u8,
                                         ((raw_addr >> 8) & 0xFF) as u8,
                                         ((raw_addr >> 0) & 0xFF) as u8);

                Ok(DnsRecord::A {
                    domain,
                    addr,
                    ttl
                })
            },
            _ => {
                buffer.step(data_len as usize)?;
                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A { ref domain, ref addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            },
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        }
    }
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.qdcount {
            let mut question = DnsQuestion::new("".to_string(), QType::A);
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.ancount {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        
        for _ in 0..result.header.nscount {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        
        for _ in 0..result.header.arcount {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }
        
        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.qdcount = self.questions.len() as u16;
        self.header.ancount = self.answers.len() as u16;
        self.header.nscount = self.authorities.len() as u16;
        self.header.arcount = self.resources.len() as u16;

        self.header.write(buffer)?;

        for q in &self.questions {
            q.write(buffer)?;
        }

        for rec in &self.answers {
            rec.write(buffer)?;
        }

        for rec in &self.authorities {
            rec.write(buffer)?;
        }

        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
    
    pub fn print(&self) {
        println!("{:?}", &self.header);
        for q in &self.questions {
            println!("{:?}", q);
        }
        println!("Answers:");
        for rec in &self.answers {
            println!("{:?}", rec);
        }
        println!("Authorities:");
        for rec in &self.authorities {
            println!("{:?}", rec);
        }
        println!("Resources:");
        for rec in &self.resources {
            println!("{:?}", rec);
        }
    }
}
