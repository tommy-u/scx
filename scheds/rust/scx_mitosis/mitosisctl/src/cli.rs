use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = crate::LONG_HELP)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List available BPF maps
    List,
    /// Get value of a map entry
    Get {
        /// Map name
        map: String,
        /// Key to look up
        key: u32,
    },
    /// Set value of a map entry
    Set {
        /// Map name
        map: String,
        /// Key to update
        key: u32,
        /// Value to set
        value: u32,
    },
    Topology,
}
