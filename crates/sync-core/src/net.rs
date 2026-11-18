//! The network front door: framing, request reading and reply writing.
//!
//! This is the code that faces the network and therefore the code an attacker
//! can drive. It is written to be boring: fixed-size reads, one request per
//! connection, strict timeouts, and no interpretation beyond what
//! `sync-wire`'s decoder does.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use sync_wire::{Op, Params, Request, Response, Status, REQUEST_LEN, RESPONSE_LEN};

/// A reply handed back to a network peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Status shown to the peer.
    pub status: Status,
    /// Detail code, if any.
    pub detail: u8,
}

impl From<Response> for Reply {
    fn from(r: Response) -> Self {
        Reply {
            status: r.status,
            detail: r.detail,
        }
    }
}

impl Reply {
    /// Encode as a wire response, so both deployments speak one format.
    pub fn to_response(self) -> Response {
        Response::new(self.status, self.detail)
    }
}

/// Read one request frame from `stream`.
///
/// On a short read, a timeout, or a bad frame, returns `Err`. The caller closes
/// the connection; it never retries within the same connection, which keeps
/// state machine complexity — and attack surface — minimal.
pub fn read_request<S: Read>(stream: &mut S) -> io::Result<Result<Request, u8>> {
    let mut buf = [0u8; REQUEST_LEN];
    match stream.read_exact(&mut buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Err(1)),
        Err(e) => return Err(e),
    }
    Ok(Request::decode(&buf).map_err(|_| 2u8))
}

/// Write one response frame.
pub fn write_response<S: Write>(stream: &mut S, reply: Reply) -> io::Result<()> {
    stream.write_all(&reply.to_response().encode())?;
    stream.flush()
}

/// A request bound to a sequence number, used by clients.
pub fn make_request(op: Op, seq: u64, nonce: [u8; 32], params: Params) -> Request {
    Request {
        op,
        seq,
        nonce,
        params,
    }
}

/// A listening server that treats each connection as exactly one request.
pub struct Server {
    listener: TcpListener,
    timeout: Duration,
}

impl Server {
    /// Bind to `addr`.
    pub fn bind(addr: &str, timeout: Duration) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Server { listener, timeout })
    }

    /// The local address actually bound.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, invoking `handle` once per request.
    ///
    /// `handle` receives the decoded request (or the error code that replaced
    /// it) and returns the reply. It is never called twice for one connection.
    pub fn serve<F>(self, mut handle: F) -> io::Result<()>
    where
        F: FnMut(Result<Request, u8>) -> Reply,
    {
        for incoming in self.listener.incoming() {
            let mut stream = match incoming {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = stream.set_read_timeout(Some(self.timeout));
            let _ = stream.set_write_timeout(Some(self.timeout));
            let _ = stream.set_nodelay(true);
            let _ = handle_connection(&mut stream, &mut handle);
        }
        Ok(())
    }
}

fn handle_connection<S, F>(stream: &mut S, handle: &mut F) -> io::Result<()>
where
    S: Read + Write,
    F: FnMut(Result<Request, u8>) -> Reply,
{
    let request = read_request(stream)?;
    let reply = handle(request);
    write_response(stream, reply)
}

/// One-shot client call against a `TcpStream`.
pub fn call(stream: &mut TcpStream, req: &Request) -> io::Result<Reply> {
    stream.write_all(&req.encode())?;
    stream.flush()?;
    let mut buf = [0u8; RESPONSE_LEN];
    stream.read_exact(&mut buf)?;
    let resp = Response::decode(&buf).map_err(|_| io::Error::other("bad response frame"))?;
    Ok(resp.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> Request {
        Request {
            op: Op::Health,
            seq: 1,
            nonce: [5u8; 32],
            params: Params::None,
        }
    }

    #[test]
    fn frame_round_trip_over_a_reader() {
        let frame = sample().encode();
        let mut cursor = Cursor::new(frame.to_vec());
        let got = read_request(&mut cursor).unwrap().unwrap();
        assert_eq!(got, sample());
    }

    #[test]
    fn short_frame_is_rejected_without_panicking() {
        let mangled = sample().encode()[..REQUEST_LEN - 1].to_vec();
        let mut cursor = Cursor::new(mangled);
        let got = read_request(&mut cursor).unwrap();
        assert_eq!(got, Err(1));
    }

    #[test]
    fn oversize_is_ignored_beyond_one_frame() {
        // Two frames back to back: the first must decode, the extra bytes are
        // left for a subsequent connection or discarded with it.
        let mut bytes = sample().encode().to_vec();
        bytes.extend_from_slice(&sample().encode());
        let mut cursor = Cursor::new(bytes);
        assert!(read_request(&mut cursor).unwrap().is_ok());
        // Cursor still has a full second frame available, but the server never
        // reads a second request from one connection.
        assert_eq!(cursor.position() as usize, REQUEST_LEN);
    }

    #[test]
    fn end_to_end_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut handle = |req: Result<Request, u8>| match req {
                Ok(r) if r.op == Op::Health => Reply {
                    status: Status::Ok,
                    detail: 0,
                },
                _ => Reply {
                    status: Status::BadRequest,
                    detail: 0,
                },
            };
            handle_connection(&mut stream, &mut handle).unwrap();
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let reply = call(&mut stream, &sample()).unwrap();
        assert_eq!(reply.status, Status::Ok);
        t.join().unwrap();
    }
}
