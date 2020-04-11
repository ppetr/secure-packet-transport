#[macro_use] extern crate log;
extern crate openssl;

mod test_util;

// Holds the list of fingerprints corresponding to a given chain of X509 certificates.
#[derive(Clone, Debug)]
pub struct FingerprintChain {
    chain: Vec<openssl::hash::DigestBytes>,
}

impl FingerprintChain {
    pub fn from_cert_chain(chain: &openssl::stack::StackRef<openssl::x509::X509>) -> Result<FingerprintChain, openssl::error::ErrorStack> {
        let mut fingerprints = Vec::new();
        for cert in chain.iter() {
            fingerprints.push(cert.digest(openssl::hash::MessageDigest::sha256())?);
        }
        return Ok(FingerprintChain{ chain: fingerprints });
    }
}

pub fn connect<S, F>(stream: S, verify: F) -> Result<openssl::ssl::SslStream<S>, openssl::ssl::HandshakeError<S>>
where S: std::io::Read + std::io::Write,
      F: Fn(&FingerprintChain) -> bool + 'static + Sync + Send,
{
    use openssl::ssl::{SslMethod, SslConnector, SslVerifyMode};
    let mut connector = SslConnector::builder(SslMethod::dtls())?;
    connector.set_verify_callback(SslVerifyMode::PEER,
                                  move |_preverified, context| {
        return match context.chain() {
            None => return false,
            Some(context_chain) => match ::FingerprintChain::from_cert_chain(context_chain) {
                Err(err) => {
                    debug!("Unable to compute fingerprints of a certificate chain: {:?}", err);
                    return false;
                },
                Ok(chain) => verify(&chain),
            },
        };
    });
    return connector.build().connect("UNSPECIFIED_DOMAIN", stream);
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind, Read, Write};
    use std::thread::{self, JoinHandle};

    use openssl::ssl::{ShutdownResult, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslStream};
    use test_util::tests::Channel;

    // Checks the SSL error, and if it is ZERO_RETURN (which means the connection has been closed
    // already), returns ShutdownResult::Received.
    // Wraps any SSL error into an io::Error.
    fn allow_zero_return(result: Result<ShutdownResult, openssl::ssl::Error>) -> Result<ShutdownResult, Error> {
        match result {
            Err(e) if e.code() == openssl::ssl::ErrorCode::ZERO_RETURN =>
                Ok(ShutdownResult::Received),
            Err(e) => Err(Error::new(ErrorKind::ConnectionAborted, e)),
            Ok(value) => Ok(value),
        }
    }

    // Performs the full shutdown procedure of a given SslStream. If the stream has already been
    // shut down from this or the other side, returns successfully as well.
    fn gracefully_shutdown<S: Read + Write>(stream: &mut SslStream<S>) -> Result<(), Error> {
        match allow_zero_return(stream.shutdown())? {
            ShutdownResult::Received => Ok(()),
            ShutdownResult::Sent => match allow_zero_return(stream.shutdown())? {
                ShutdownResult::Received => Ok(()),
                ShutdownResult::Sent => Err(Error::new(ErrorKind::ConnectionAborted,
                                                       "Unexpected ShutdownResult::Sent")),
            }
        }
    }

    pub struct Server {
        handle: Option<JoinHandle<()>>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if !thread::panicking() {
                self.handle.take().unwrap().join().unwrap();
            }
        }
    }

    impl Server {
        fn builder(channel: Channel) -> Builder {
            let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
            ctx.set_certificate_chain_file("test/cert.pem").unwrap();
            ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
                .unwrap();

            Builder {
                ctx,
                channel,
            }
        }
    }

    pub struct Builder {
        ctx: SslContextBuilder,
        channel: Channel,
    }

    impl Builder {

        pub fn build(self) -> Server {
            let ctx = self.ctx.build();
            let channel = self.channel;

            let thread = thread::Builder::new().name(String::from("server"));
            let handle = thread.spawn(move || {
                    // TODO: Use SslAcceptor here.
                    let ssl = Ssl::new(&ctx).unwrap();
                    println!("Server is waiting for a SSL connection");
                    let r = ssl.accept(channel);
                    println!("Accept call result: {:?}", r.as_ref().err());
                    let mut socket = r.unwrap();
                    socket.write_all(b"Test message").unwrap();
                    println!("Server shutting down.");
                    gracefully_shutdown(&mut socket).unwrap();
                    println!("Server finished.");
            }).unwrap();

            Server {
                handle: Some(handle),
            }
        }
    }

    #[test]
    fn verify_fingerprint() {
        let (server_channel, client_channel) = Channel::create_pair(0);

        let _server = Server::builder(server_channel).build();

        let mut stream = ::connect(client_channel, move |chain| {
            println!("Fingerprint chain: {:?}", chain);
            assert_eq!(chain.chain.len(), 1);
            return chain.chain[0].as_ref() == [71, 18, 185, 57, 251, 203, 66, 166, 181, 16, 27, 66, 19, 154, 37, 177, 79, 129, 180, 24, 250, 202, 189, 55, 135, 70, 241, 47, 133, 204, 101, 68];
        }).unwrap();
        let mut res = vec![];
        stream.read_to_end(&mut res).unwrap();
        println!("Client received: {}", String::from_utf8_lossy(&res));
        println!("Client shutting down.");
        gracefully_shutdown(&mut stream).unwrap();
        println!("Client finished");
    }
}
