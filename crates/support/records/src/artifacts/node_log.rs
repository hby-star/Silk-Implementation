use super::RecordError;
pub use beacon_node::observer::{
    NODE_LOG_SCHEMA, NodeEvent, TRANSPORT_PROFILE, WIRE_ACCOUNTING_MODE,
};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub struct NodeLogger {
    path: PathBuf,
    writer: BufWriter<fs::File>,
    next_sequence: u64,
}

impl NodeLogger {
    pub fn create(root: &Path, node_id: u32) -> Result<Self, RecordError> {
        fs::create_dir_all(root)?;
        let path = root.join(format!("node-{node_id:04}.jsonl"));
        Ok(Self {
            path: path.clone(),
            writer: BufWriter::new(OpenOptions::new().create_new(true).write(true).open(path)?),
            next_sequence: 0,
        })
    }

    pub fn record(&mut self, event: &NodeEvent) -> Result<(), RecordError> {
        let mut event = event.clone();
        event.node_sequence = self.next_sequence;
        serde_json::to_writer(&mut self.writer, &event)?;
        self.writer.write_all(b"\n")?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<String, RecordError> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        let digest = hex::encode(crypto_primitives::hash::sha256(&fs::read(&self.path)?));
        let checksum_path = self.path.with_extension("jsonl.sha256");
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| RecordError::Validation("node log has no file name".into()))?
            .to_string_lossy();
        fs::write(checksum_path, format!("{digest}  {file_name}\n"))?;
        Ok(digest)
    }
}

impl beacon_node::observer::NodeObserver for NodeLogger {
    fn record(&mut self, event: &NodeEvent) -> std::io::Result<()> {
        NodeLogger::record(self, event).map_err(std::io::Error::other)
    }
    fn artifact(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        if !matches!(name, "node.json" | "summary.json" | "complete") {
            return Err(std::io::Error::other("unsupported node artifact"));
        }
        fs::write(self.path.parent().unwrap().join(name), bytes)
    }
    fn finish(&mut self) -> std::io::Result<String> {
        NodeLogger::finish(self).map_err(std::io::Error::other)
    }
}
