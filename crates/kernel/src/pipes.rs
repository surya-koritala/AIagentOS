//! Agent Pipes — unidirectional data streams between agents.
//!
//! Like Unix pipes. One agent writes, another reads. Used for chaining
//! agent output → input (agent1 | agent2).

use tokio::sync::mpsc;

use crate::agent_struct::AgentId;

/// A pipe (one write end, one read end).
pub struct Pipe {
    pub read_end: PipeRead,
    pub write_end: PipeWrite,
}

/// Read end of a pipe.
pub struct PipeRead {
    rx: mpsc::Receiver<Vec<u8>>,
    pub owner: AgentId,
    pub closed: bool,
}

/// Write end of a pipe.
pub struct PipeWrite {
    tx: mpsc::Sender<Vec<u8>>,
    pub owner: AgentId,
    pub closed: bool,
}

impl Pipe {
    /// Create a new pipe with given buffer size.
    pub fn new(reader: AgentId, writer: AgentId, buffer: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer);
        Self {
            read_end: PipeRead { rx, owner: reader, closed: false },
            write_end: PipeWrite { tx, owner: writer, closed: false },
        }
    }
}

impl PipeWrite {
    /// Write data to the pipe.
    pub async fn write(&self, data: Vec<u8>) -> Result<usize, &'static str> {
        if self.closed { return Err("broken pipe (EPIPE)"); }
        let len = data.len();
        self.tx.send(data).await.map_err(|_| "broken pipe (EPIPE)")?;
        Ok(len)
    }

    /// Write string data.
    pub async fn write_str(&self, s: &str) -> Result<usize, &'static str> {
        self.write(s.as_bytes().to_vec()).await
    }

    /// Close the write end.
    pub fn close(&mut self) { self.closed = true; }
}

impl PipeRead {
    /// Read data from the pipe (blocks until data available or pipe closed).
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        if self.closed { return None; }
        self.rx.recv().await
    }

    /// Read as string.
    pub async fn read_str(&mut self) -> Option<String> {
        self.read().await.map(|b| String::from_utf8_lossy(&b).to_string())
    }

    /// Try to read without blocking.
    pub fn try_read(&mut self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok()
    }

    /// Close the read end.
    pub fn close(&mut self) { self.closed = true; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pipe_write_and_read() {
        let pipe = Pipe::new(1, 2, 32);
        let mut read = pipe.read_end;
        let write = pipe.write_end;

        write.write_str("hello").await.unwrap();
        let data = read.read_str().await.unwrap();
        assert_eq!(data, "hello");
    }

    #[tokio::test]
    async fn pipe_multiple_messages() {
        let pipe = Pipe::new(1, 2, 32);
        let mut read = pipe.read_end;
        let write = pipe.write_end;

        write.write_str("msg1").await.unwrap();
        write.write_str("msg2").await.unwrap();
        assert_eq!(read.read_str().await.unwrap(), "msg1");
        assert_eq!(read.read_str().await.unwrap(), "msg2");
    }

    #[tokio::test]
    async fn pipe_closed_write_fails() {
        let pipe = Pipe::new(1, 2, 32);
        let _read = pipe.read_end;
        let mut write = pipe.write_end;
        write.close();
        let result = write.write_str("fail").await;
        assert!(result.is_err());
    }

    #[test]
    fn try_read_empty() {
        let pipe = Pipe::new(1, 2, 32);
        let mut read = pipe.read_end;
        assert!(read.try_read().is_none());
    }
}
