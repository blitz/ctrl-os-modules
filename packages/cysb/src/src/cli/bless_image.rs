use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use super::sign_file::SignOpts;

///
#[derive(Debug, Args)]
pub struct Opts {
    /// A disk image to bless.
    ///
    /// This must be a GPT-partitioned disk image with a ESP. This command will modify it in-place. systemd-boot and any
    /// UKI will be signed.
    #[arg(required = true)]
    disk_image: PathBuf,

    #[command(flatten)]
    sign_opts: SignOpts,
}

impl Opts {
    pub fn run(&self) -> Result<()> {
        todo!()
    }
}
