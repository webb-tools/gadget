use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Shell Manager",
    about = "An program executor that connects to the Tangle network and runs protocols dynamically on the fly"
)]
pub struct BlueprintManagerConfig {
    /// The path to the shell configuration file
    #[structopt(parse(from_os_str), short = "s", long = "shell-config")]
    pub gadget_config: Option<PathBuf>,
    /// The verbosity level, can be used multiple times
    #[structopt(long, short = "v", parse(from_occurrences))]
    pub verbose: i32,
    /// Whether to use pretty logging
    #[structopt(long)]
    pub pretty: bool,
    /// An optional unique string identifier for the blueprint manager to differentiate between multiple
    /// running instances of a BlueprintManager (mostly for debugging purposes)
    #[structopt(long, short = "id")]
    pub instance_id: Option<String>,
}
