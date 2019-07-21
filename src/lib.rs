extern crate openssl;

#[cfg(test)]
mod tests {

    use std::io::Write;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod};
    use openssl::x509;

    pub struct Server {
	    handle: Option<JoinHandle<()>>,
	    addr: SocketAddr,
    }

    impl Drop for Server {
	fn drop(&mut self) {
	    if !thread::panicking() {
		self.handle.take().unwrap().join().unwrap();
	    }
	}
    }

    impl Server {
	pub fn builder() -> Builder {
	    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
	    ctx.set_certificate_chain_file("test/cert.pem").unwrap();
	    ctx.set_private_key_file("test/key.pem", x509::X509_FILETYPE_PEM)
		.unwrap();

	    Builder {
		ctx,
	    }
	}

	pub fn connect_tcp(&self) -> TcpStream {
	    TcpStream::connect(self.addr).unwrap()
	}
    }

    pub struct Builder {
	ctx: SslContextBuilder,
    }

    impl Builder {
	pub fn build(self) -> Server {
	    let ctx = self.ctx.build();
	    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
	    let addr = socket.local_addr().unwrap();

            let thread = thread::Builder::new().name(String::from("server"));
	    let handle = thread.spawn(move || {
		    let socket = socket.accept().unwrap().0;
		    let ssl = Ssl::new(&ctx).unwrap();
		    let r = ssl.accept(socket);
                    let mut socket = r.unwrap();
                    socket.write_all(&[0]).unwrap();
	    }).unwrap();

	    Server {
		handle: Some(handle),
		addr,
	    }
	}
    }

    #[test]
    fn connect_server() {
	use openssl::hash::MessageDigest;
	use openssl::ssl::{SslMethod, SslConnectorBuilder, SSL_VERIFY_PEER};
	use std::io::{Read, Write};

        let server = Server::builder().build();

	let mut connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
        connector.set_verify_callback(SSL_VERIFY_PEER,
                                      move |_preverified, context| {
            let fingerprint = context.current_cert().unwrap().fingerprint(MessageDigest::sha256()).unwrap();
            println!("{:?}", fingerprint);
            return fingerprint == [71, 18, 185, 57, 251, 203, 66, 166, 181, 16, 27, 66, 19, 154, 37, 177, 79, 129, 180, 24, 250, 202, 189, 55, 135, 70, 241, 47, 133, 204, 101, 68];
        });
        let connector = connector.build();

	let mut stream = connector.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(server.connect_tcp()).unwrap();
	stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
	let mut res = vec![];
	stream.read_to_end(&mut res).unwrap();
	println!("{}", String::from_utf8_lossy(&res));
    }
}
