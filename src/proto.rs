use acl::{Acl, Permission};
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use consts::{KeeperState, WatchedEventType, ZkError};
use data::Stat;
use multi::{Op, OpResult};
use zookeeper::ZkResult;
use std::convert::From;
use std::io::{Cursor, Read, Write, Result, Error, ErrorKind};
use watch::WatchedEvent;

/// Operation code for messages. See `RequestHeader`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCode {
    Auth = 100,
    Create = 1,
    Delete = 2,
    Exists = 3,
    GetAcl = 6,
    SetAcl = 7,
    GetChildren = 8,
    GetData = 4,
    SetData = 5,
    Ping = 11,
    Check = 13,
    Transaction = 14,
    CloseSession = -11,
}

pub type ByteBuf = Cursor<Vec<u8>>;

pub trait ReadFrom: Sized {
    fn read_from<R: Read>(read: &mut R) -> Result<Self>;
}

pub trait WriteTo {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()>;

    fn to_len_prefixed_buf(&self) -> Result<ByteBuf> {
        let mut buf = Cursor::new(Vec::new());
        buf.set_position(4);
        try!(self.write_to(&mut buf));
        let len = buf.position() - 4;
        buf.set_position(0);
        try!(buf.write_i32::<BigEndian>(len as i32));
        buf.set_position(0);
        Ok(buf)
    }
}

pub fn to_len_prefixed_buf<Request: WriteTo>(rh: RequestHeader, req: Request) -> Result<ByteBuf> {
    let mut buf = Cursor::new(Vec::new());
    buf.set_position(4);
    try!(rh.write_to(&mut buf));
    try!(req.write_to(&mut buf));
    let len = buf.position() - 4;
    buf.set_position(0);
    try!(buf.write_i32::<BigEndian>(len as i32));
    buf.set_position(0);
    Ok(buf)
}

fn error(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidInput, msg)
}

trait StringReader: Read {
    fn read_string(&mut self) -> Result<String>;
}

pub trait BufferReader: Read {
    fn read_buffer(&mut self) -> Result<Vec<u8>>;
}

impl<R: Read> StringReader for R {
    fn read_string(&mut self) -> Result<String> {
        let raw = try!(self.read_buffer());
        Ok(String::from_utf8(raw).unwrap())
    }
}

// A buffer is an u8 string prefixed with it's length as i32
impl<R: Read> BufferReader for R {
    fn read_buffer(&mut self) -> Result<Vec<u8>> {
        let len = try!(self.read_i32::<BigEndian>());
        let len = if len < 0 {
            0
        } else {
            len as usize
        };
        let mut buf = vec![0; len];
        let read = try!(self.read(&mut buf));
        if read == len {
            Ok(buf)
        } else {
            Err(error("read_buffer failed"))
        }
    }
}

impl WriteTo for u8 {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(writer.write_u8(*self));
        Ok(())
    }
}

impl WriteTo for String {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(writer.write_i32::<BigEndian>(self.len() as i32));
        writer.write_all(self.as_ref())
    }
}

impl<T: WriteTo> WriteTo for Vec<T> {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(writer.write_i32::<BigEndian>(self.len() as i32));
        let mut res = Ok(());
        for elem in self.iter() {
            res = elem.write_to(writer);
            if res.is_err() {
                return res;
            }
        }
        res
    }
}

impl ReadFrom for Acl {
    fn read_from<R: Read>(read: &mut R) -> Result<Acl> {
        Ok(Acl {
            perms: Permission::from_raw(read.read_u32::<BigEndian>()?),
            scheme: read.read_string()?,
            id: read.read_string()?,
        })
    }
}

impl WriteTo for Acl {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_u32::<BigEndian>(self.perms.code())?;
        self.scheme.write_to(writer)?;
        self.id.write_to(writer)
    }
}

impl ReadFrom for Stat {
    fn read_from<R: Read>(read: &mut R) -> Result<Stat> {
        Ok(Stat {
            czxid: try!(read.read_i64::<BigEndian>()),
            mzxid: try!(read.read_i64::<BigEndian>()),
            ctime: try!(read.read_i64::<BigEndian>()),
            mtime: try!(read.read_i64::<BigEndian>()),
            version: try!(read.read_i32::<BigEndian>()),
            cversion: try!(read.read_i32::<BigEndian>()),
            aversion: try!(read.read_i32::<BigEndian>()),
            ephemeral_owner: try!(read.read_i64::<BigEndian>()),
            data_length: try!(read.read_i32::<BigEndian>()),
            num_children: try!(read.read_i32::<BigEndian>()),
            pzxid: try!(read.read_i64::<BigEndian>()),
        })
    }
}

pub struct ConnectRequest {
    protocol_version: i32,
    last_zxid_seen: i64,
    timeout: i32,
    session_id: i64,
    passwd: Vec<u8>,
    read_only: bool,
}

impl ConnectRequest {
    pub fn from(conn_resp: &ConnectResponse, last_zxid_seen: i64) -> ConnectRequest {
        ConnectRequest {
            protocol_version: conn_resp.protocol_version,
            last_zxid_seen: last_zxid_seen,
            timeout: conn_resp.timeout as i32,
            session_id: conn_resp.session_id,
            passwd: conn_resp.passwd.clone(),
            read_only: conn_resp.read_only,
        }
    }
}

impl WriteTo for ConnectRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(writer.write_i32::<BigEndian>(self.protocol_version));
        try!(writer.write_i64::<BigEndian>(self.last_zxid_seen));
        try!(writer.write_i32::<BigEndian>(self.timeout));
        try!(writer.write_i64::<BigEndian>(self.session_id));
        try!(self.passwd.write_to(writer));
        try!(writer.write_u8(self.read_only as u8));
        Ok(())
    }
}

#[derive(Debug)]
pub struct ConnectResponse {
    protocol_version: i32,
    pub timeout: u64, // is handled as i32
    pub session_id: i64,
    passwd: Vec<u8>,
    pub read_only: bool,
}

impl ConnectResponse {
    pub fn initial(timeout: u64) -> ConnectResponse {
        ConnectResponse {
            protocol_version: 0,
            timeout: timeout,
            session_id: 0,
            passwd: vec![0;16],
            read_only: false,
        }
    }
}

impl ReadFrom for ConnectResponse {
    fn read_from<R: Read>(reader: &mut R) -> Result<ConnectResponse> {
        Ok(ConnectResponse {
            protocol_version: try!(reader.read_i32::<BigEndian>()),
            timeout: try!(reader.read_i32::<BigEndian>()) as u64,
            session_id: try!(reader.read_i64::<BigEndian>()),
            passwd: try!(reader.read_buffer()),
            read_only: try!(reader.read_u8()) != 0,
        })
    }
}

pub struct RequestHeader {
    pub xid: i32,
    pub opcode: OpCode,
}

impl WriteTo for RequestHeader {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(writer.write_i32::<BigEndian>(self.xid));
        try!(writer.write_i32::<BigEndian>(self.opcode as i32));
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReplyHeader {
    pub xid: i32,
    pub zxid: i64,
    pub err: i32,
}

impl ReadFrom for ReplyHeader {
    fn read_from<R: Read>(read: &mut R) -> Result<ReplyHeader> {
        Ok(ReplyHeader {
            xid: try!(read.read_i32::<BigEndian>()),
            zxid: try!(read.read_i64::<BigEndian>()),
            err: try!(read.read_i32::<BigEndian>()),
        })
    }
}

pub struct CreateRequest {
    pub path: String,
    pub data: Vec<u8>,
    pub acl: Vec<Acl>,
    pub flags: i32,
}

impl WriteTo for CreateRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(self.path.write_to(writer));
        try!(self.data.write_to(writer));
        try!(self.acl.write_to(writer));
        try!(writer.write_i32::<BigEndian>(self.flags));
        Ok(())
    }
}

pub struct CreateResponse {
    pub path: String,
}

impl ReadFrom for CreateResponse {
    fn read_from<R: Read>(reader: &mut R) -> Result<CreateResponse> {
        Ok(CreateResponse { path: try!(reader.read_string()) })
    }
}

pub struct DeleteRequest {
    pub path: String,
    pub version: i32,
}

impl WriteTo for DeleteRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(self.path.write_to(writer));
        try!(writer.write_i32::<BigEndian>(self.version));
        Ok(())
    }
}

pub struct StringAndBoolRequest {
    pub path: String,
    pub watch: bool,
}

impl WriteTo for StringAndBoolRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(self.path.write_to(writer));
        try!(writer.write_u8(self.watch as u8));
        Ok(())
    }
}

pub type ExistsRequest = StringAndBoolRequest;
pub type ExistsResponse = StatResponse;

pub struct StatResponse {
    pub stat: Stat,
}

impl ReadFrom for StatResponse {
    fn read_from<R: Read>(read: &mut R) -> Result<StatResponse> {
        Ok(StatResponse { stat: try!(Stat::read_from(read)) })
    }
}

pub struct GetAclRequest {
    pub path: String,
}

impl WriteTo for GetAclRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.path.write_to(writer)
    }
}

pub struct GetAclResponse {
    pub acl_stat: (Vec<Acl>, Stat),
}

impl ReadFrom for GetAclResponse {
    fn read_from<R: Read>(reader: &mut R) -> Result<GetAclResponse> {
        let len = try!(reader.read_i32::<BigEndian>());
        let mut acl = Vec::with_capacity(len as usize);
        for _ in 0..len {
            acl.push(try!(Acl::read_from(reader)));
        }
        let stat = try!(Stat::read_from(reader));
        Ok(GetAclResponse { acl_stat: (acl, stat) })
    }
}

pub struct SetAclRequest {
    pub path: String,
    pub acl: Vec<Acl>,
    pub version: i32,
}

impl WriteTo for SetAclRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(self.path.write_to(writer));
        try!(self.acl.write_to(writer));
        try!(writer.write_i32::<BigEndian>(self.version));
        Ok(())
    }
}

pub type SetAclResponse = StatResponse;

pub struct SetDataRequest {
    pub path: String,
    pub data: Vec<u8>,
    pub version: i32,
}

impl WriteTo for SetDataRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(self.path.write_to(writer));
        try!(self.data.write_to(writer));
        try!(writer.write_i32::<BigEndian>(self.version));
        Ok(())
    }
}

pub type SetDataResponse = StatResponse;

pub type GetChildrenRequest = StringAndBoolRequest;

pub struct GetChildrenResponse {
    pub children: Vec<String>,
}

impl ReadFrom for GetChildrenResponse {
    fn read_from<R: Read>(reader: &mut R) -> Result<GetChildrenResponse> {
        let len = try!(reader.read_i32::<BigEndian>());
        let mut children = Vec::with_capacity(len as usize);
        for _ in 0..len {
            children.push(try!(reader.read_string()));
        }
        Ok(GetChildrenResponse { children: children })
    }
}

pub type GetDataRequest = StringAndBoolRequest;

pub struct GetDataResponse {
    pub data_stat: (Vec<u8>, Stat),
}

impl ReadFrom for GetDataResponse {
    fn read_from<R: Read>(reader: &mut R) -> Result<GetDataResponse> {
        let data = try!(reader.read_buffer());
        let stat = try!(Stat::read_from(reader));
        Ok(GetDataResponse { data_stat: (data, stat) })
    }
}

pub struct TransactionRequest<'a> {
    pub ops: &'a [Op]
}

impl <'a> WriteTo for TransactionRequest<'a> {
    fn write_to(&self, writer: &mut Write) -> Result<()> {
        for ref op in self.ops {
            let type_code = match *op {
                &Op::Check { ref path, ref version } => OpCode::Check,
                &Op::Create { ref path, ref data, ref acl, ref mode } => OpCode::Create,
                &Op::Delete { ref path, ref version } => OpCode::Delete,
                &Op::SetData { ref path, ref data, ref version } => OpCode::SetData,
            };

            // Header for each entry in the multi:
            writer.write_i32::<BigEndian>(type_code as i32)?;
            writer.write_u8(0 as u8)?;          // "done": This isn't the closing entry
            writer.write_i32::<BigEndian>(-1)?; // "err":  We haven't experienced an error

            match *op {
                &Op::Check { ref path, ref version } => {
                    path.write_to(writer)?;
                    writer.write_i32::<BigEndian>(version.unwrap_or(-1))?;
                },
                &Op::Create { ref path, ref data, ref acl, ref mode } => {
                    path.write_to(writer)?;
                    data.write_to(writer)?;
                    acl.write_to(writer)?;
                    writer.write_i32::<BigEndian>(mode.clone() as i32)?;
                },
                &Op::Delete { ref path, ref version } => {
                    path.write_to(writer)?;
                    writer.write_i32::<BigEndian>(version.unwrap_or(-1))?;
                },
                &Op::SetData { ref path, ref data, ref version } => {
                    path.write_to(writer)?;
                    data.write_to(writer)?;
                    writer.write_i32::<BigEndian>(version.unwrap_or(-1))?;
                }
            }
        }

        // Mark end of operation with this thing that looks like the per-entry header
        writer.write_i32::<BigEndian>(-1)?;
        writer.write_u8(1)?;
        writer.write_i32::<BigEndian>(-1)?;

        Ok(())
    }
}

pub struct TransactionResponse {
    pub responses: Vec<ZkResult<OpResult>>,
}

#[derive(Debug, EnumConvertFromInt)]
enum Completion {
    Error = -1,
    Empty = 0,
    Stat = 1,
    String = 6,
}

fn read_transaction_header<R: Read>(reader: &mut R) -> Result<(Completion, bool, i32)> {
    let type_code = reader.read_i32::<BigEndian>()?;
    let done = reader.read_u8()?;
    let err = reader.read_i32::<BigEndian>()?;

    Ok((Completion::from(type_code), done != 0, err))
}

impl ReadFrom for TransactionResponse {
    fn read_from<R: Read>(reader: &mut R) -> Result<TransactionResponse> {
        Ok(TransactionResponse {responses: vec![] } )

        // TODO: This code is wrong, but it's unclear why...
        /*let mut results: Vec<ZkResult<OpResult>> = vec![];
        let mut result_idx = -1;
        // I don't know the proper Rust way to write this:
        // `for (size_t result_idx = 0; true; ++result_idx)`
        loop {
            result_idx += 1;
            let (type_code, done, err) = read_transaction_header(&mut reader)?;

            let entry = match type_code {
                Completion::Error => {
                    let err_code = reader.read_i32::<BigEndian>()?;
                    Err(ZkError::from(err_code))
                },
                Completion::Empty => {
                    Ok(OpResult::Empty{})
                },
                Completion::Stat => {
                    Ok(OpResult::SetData{ stat: Stat::read_from(reader)? })
                },
                Completion::String => {
                    Ok(OpResult::Create{ path: reader.read_string()? })
                },
                _ => {
                    return Err(Error::new(ErrorKind::InvalidInput,
                                          format!("Received unknown code {:?}", type_code)))
                }
            };
            results.push(entry);

            if done {
                break;
            }
        }
        Ok(TransactionResponse {responses: results })*/
    }
}

pub struct AuthRequest {
    pub typ: i32,
    pub scheme: String,
    pub auth: Vec<u8>,
}

impl WriteTo for AuthRequest {
    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        try!(writer.write_i32::<BigEndian>(self.typ));
        try!(self.scheme.write_to(writer));
        self.auth.write_to(writer)
    }
}

pub struct EmptyRequest;
pub struct EmptyResponse;

impl WriteTo for EmptyRequest {
    fn write_to(&self, _: &mut dyn Write) -> Result<()> {
        Ok(())
    }
}

impl ReadFrom for EmptyResponse {
    fn read_from<R: Read>(_: &mut R) -> Result<EmptyResponse> {
        Ok(EmptyResponse)
    }
}

impl ReadFrom for WatchedEvent {
    fn read_from<R: Read>(reader: &mut R) -> Result<WatchedEvent> {
        let type_raw = try!(reader.read_i32::<BigEndian>());
        let state_raw = try!(reader.read_i32::<BigEndian>());
        let path = try!(reader.read_string());
        let event_type = WatchedEventType::from(type_raw);
        let state = KeeperState::from(state_raw);
        Ok(WatchedEvent {
            event_type: event_type,
            keeper_state: state,
            path: Some(path),
        })
    }
}
