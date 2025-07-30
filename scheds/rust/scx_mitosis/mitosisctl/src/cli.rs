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
    /// Get state of a map
    Get {
        /// Map name
        map: String,
    },
    /// Load map from topology
    Set {
        /// Map name
        map: String,
    },
    Topology,
}
