use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = crate::LONG_HELP)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Splash screen
    Splash,
    /// List available BPF maps
    List,
    /// Get state of a map
    Get {
        /// Map name
        map: String,
    },
    /// Load map from topology or from file (if -f is specified)
    Set {
        /// Map name
        map: String,
        /// Optional topology file ("-" for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Print processor topology
    Topology,
}
