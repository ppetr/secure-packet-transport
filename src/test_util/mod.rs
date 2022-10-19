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

#[cfg(test)]
pub mod tests {
    use std::fmt::Display;
    use std::io;
    use std::io::{Read, Write};
    use std::sync::mpsc::{sync_channel, Receiver, RecvError, SyncSender};

    #[derive(Debug)]
    pub struct Channel {
        writer: SyncSender<Vec<u8>>,
        reader: Receiver<Vec<u8>>,
    }

    impl Channel {
        pub fn create_pair(bound: usize) -> (Channel, Channel) {
            let (sender1, receiver1) = sync_channel(bound);
            let (sender2, receiver2) = sync_channel(bound);
            (
                Channel {
                    writer: sender1,
                    reader: receiver2,
                },
                Channel {
                    writer: sender2,
                    reader: receiver1,
                },
            )
        }

        fn to_io_result<E>(err: E) -> io::Error
        where
            E: Display,
        {
            use std::io::{Error, ErrorKind};
            Error::new(ErrorKind::BrokenPipe, err.to_string())
        }
    }

    impl Write for Channel {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writer
                .send(buf.to_vec())
                .map_err(Channel::to_io_result)?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for Channel {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::cmp::min;
            let vec = match self.reader.recv() {
                Err(RecvError {}) => return Ok(0),
                Ok(payload) => payload,
            };
            // Silently truncate the value, if the buffer is too small.
            let len = min(vec.len(), buf.len());
            buf[..len].clone_from_slice(&vec[..len]);
            Ok(len)
        }
    }

    // Messages are used to test sending and receiving blocks of data.
    pub struct Message<'a> {
        pub server_sends: bool,
        pub data: &'a [u8],
    }

    impl Message<'_> {
        pub fn expect_to_read<R: std::io::Read>(reader: &mut R, data: &[u8]) {
            let mut buffer = vec![0; data.len()];
            reader.read_exact(&mut buffer).unwrap();
            assert_eq!(buffer, data, "Didn't receive expected data");
        }

        pub fn expect_eof<R: std::io::Read>(reader: &mut R) {
            let mut buffer = vec![0; 1];
            assert_eq!(reader.read(&mut buffer).unwrap(), 0, "Not EOF yet");
        }

        // Sends or receives message, depending on its 'server_sends' field and 'server' parameter.
        // Panics if the operation fails.
        pub fn send_or_receive<S>(&self, server: bool, stream: &mut S)
        where
            S: std::io::Read + std::io::Write,
        {
            if server == self.server_sends {
                stream.write_all(self.data).unwrap();
            } else {
                Message::expect_to_read(stream, self.data);
            }
        }
    }
}
