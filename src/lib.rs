// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate log;
extern crate openssl;

mod test_util;

// Holds the list of fingerprints corresponding to a given chain of X509 certificates.
#[derive(Clone, Debug)]
pub struct FingerprintChain {
    chain: Vec<openssl::hash::DigestBytes>,
}

impl FingerprintChain {
    pub fn from_cert_chain(
        chain: &openssl::stack::StackRef<openssl::x509::X509>,
    ) -> Result<FingerprintChain, openssl::error::ErrorStack> {
        let mut fingerprints = Vec::new();
        for cert in chain.iter() {
            fingerprints.push(cert.digest(openssl::hash::MessageDigest::sha256())?);
        }
        return Ok(FingerprintChain {
            chain: fingerprints,
        });
    }
}

pub trait Configuration {
    fn configure(
        self,
        context: &mut openssl::ssl::SslContextBuilder,
    ) -> Result<(), openssl::error::ErrorStack>;
}

// TODO: Investigate the option of returning a Result from 'F' and passing errors to ErrorStack.
fn set_verify_fingerprint_callback<F>(context: &mut openssl::ssl::SslContextBuilder, callback: F)
where
    F: Fn(&FingerprintChain) -> bool + 'static + Sync + Send,
{
    context.set_verify_callback(
        openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        move |_preverified, ctx| match ctx.chain() {
            None => false,
            Some(context_chain) => match FingerprintChain::from_cert_chain(context_chain) {
                Err(err) => {
                    debug!(
                        "Unable to compute fingerprints of a certificate chain: {:?}",
                        err
                    );
                    false
                }
                Ok(chain) => callback(&chain),
            },
        },
    )
}

pub struct SimpleConfiguration {
    certificate_chain_file: Option<String>,
    private_key_pem_file: Option<String>,
    allowed_keys: Option<std::collections::HashSet<Vec<u8>>>,
}

impl Configuration for SimpleConfiguration {
    fn configure(
        self,
        context: &mut openssl::ssl::SslContextBuilder,
    ) -> Result<(), openssl::error::ErrorStack> {
        for file in self.certificate_chain_file {
            context.set_certificate_chain_file(file)?;
        }
        for file in self.private_key_pem_file {
            context.set_private_key_file(file, openssl::ssl::SslFiletype::PEM)?;
        }
        for allowed_keys in self.allowed_keys {
            set_verify_fingerprint_callback(context, move |chain| -> bool {
                match chain.chain.first() {
                    Some(digest) if allowed_keys.contains(digest.as_ref()) => true,
                    _ => false,
                }
            });
        }
        Ok(())
    }
}

pub fn connect<S, C>(
    stream: S,
    config: C,
) -> Result<openssl::ssl::SslStream<S>, openssl::ssl::HandshakeError<S>>
where
    S: std::io::Read + std::io::Write,
    C: Configuration,
{
    use openssl::ssl::{SslConnector, SslMethod};
    let mut connector = SslConnector::builder(SslMethod::dtls())?;
    config.configure(&mut connector)?;
    return connector.build().connect("UNSPECIFIED_DOMAIN", stream);
}

pub fn server<C>(config: C) -> Result<openssl::ssl::SslAcceptor, openssl::error::ErrorStack>
where
    C: Configuration,
{
    use openssl::ssl::{SslAcceptor, SslMethod};
    // See https://wiki.mozilla.org/Security/Server_Side_TLS
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::dtls())?;
    config.configure(&mut acceptor)?;
    Ok(acceptor.build())
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind, Read, Write};
    use std::thread::{self, JoinHandle};

    use openssl::ssl::{ShutdownResult, SslStream};
    use test_util::tests::{Channel, Message};

    // Checks the SSL error, and if it is ZERO_RETURN (which means the connection has been closed
    // already), returns ShutdownResult::Received.
    // Wraps any SSL error into an io::Error.
    fn allow_zero_return(
        result: Result<ShutdownResult, openssl::ssl::Error>,
    ) -> Result<ShutdownResult, Error> {
        match result {
            Err(e) if e.code() == openssl::ssl::ErrorCode::ZERO_RETURN => {
                Ok(ShutdownResult::Received)
            }
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
                ShutdownResult::Sent => Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "Unexpected ShutdownResult::Sent",
                )),
            },
        }
    }

    // Sends or receives a sequence of messages and then waits for EOF on the server or the
    // client side (exactly at one of them).
    fn expect_messages<S>(server: bool, stream: &mut S, seq: &[Message])
    where
        S: std::io::Read + std::io::Write,
    {
        for message in seq {
            message.send_or_receive(server, stream);
        }
        // Choose pseudorandomly one side that waits for the other one to close the connection.
        if (seq.len() % 2 == 0) == server {
            Message::expect_eof(stream);
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
            Builder {
                config: ::SimpleConfiguration {
                    certificate_chain_file: Some("test/cert.pem".to_string()),
                    private_key_pem_file: Some("test/key.pem".to_string()),
                    allowed_keys: None,
                },
                channel,
            }
        }
    }

    struct Builder {
        config: ::SimpleConfiguration,
        channel: Channel,
    }

    impl Builder {
        pub fn build(self) -> Server {
            let acceptor = ::server(self.config).unwrap();
            let channel = self.channel;

            let thread = thread::Builder::new().name(String::from("server"));
            let handle = thread
                .spawn(move || {
                    println!("Server is waiting for a SSL connection");
                    let r = acceptor.accept(channel);
                    println!("Accept call result: {:?}", r.as_ref().err());
                    let mut socket = r.unwrap();
                    expect_messages(/*server=*/ true, &mut socket, TEST_MESSAGE_SEQUENCE);
                    println!("Server shutting down.");
                    gracefully_shutdown(&mut socket).unwrap();
                    println!("Server finished.");
                })
                .unwrap();

            Server {
                handle: Some(handle),
            }
        }
    }

    const TEST_MESSAGE_SEQUENCE: &[Message] = &[
        Message {
            server_sends: true,
            data: b"Test message",
        },
        Message {
            server_sends: false,
            data: b"Test reply\x00\xaa\x55\xff",
        },
        Message {
            server_sends: false,
            data: b"\x00\xaa\x55\xff",
        },
        Message {
            server_sends: true,
            data: b"Another test message",
        },
        Message {
            server_sends: true,
            data: b"Final test message",
        },
    ];

    #[test]
    fn verify_fingerprint() {
        let (server_channel, client_channel) = Channel::create_pair(1);

        let _server = Server::builder(server_channel).build();

        println!("Client is connecting to the server");
        let config = ::SimpleConfiguration {
            certificate_chain_file: None,
            private_key_pem_file: None,
            allowed_keys: Some(
                [vec![
                    71, 18, 185, 57, 251, 203, 66, 166, 181, 16, 27, 66, 19, 154, 37, 177, 79, 129,
                    180, 24, 250, 202, 189, 55, 135, 70, 241, 47, 133, 204, 101, 68,
                ]]
                .iter()
                .cloned()
                .collect(),
            ),
        };
        let mut socket = ::connect(client_channel, config).unwrap();
        println!("Client is receiving data");
        expect_messages(/*server=*/ false, &mut socket, TEST_MESSAGE_SEQUENCE);
        println!("Client is shutting down.");
        gracefully_shutdown(&mut socket).unwrap();
        println!("Client finished");
    }
}
