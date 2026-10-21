use clap::{Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(
    name = "ps4save-rs",
    about = "PS4 save/PFS key tooling",
    long_about = "PS4 save/PFS key tooling. config.ini is always read from the current directory.\nAll save commands detect file type by magic (pfsSKKey) and derive the sibling automatically.\nYou can pass either the .bin (sealed key) or the image — the other is found next to it.",
    version
)]
pub struct Cli {
    /// Launch the graphical interface
    #[arg(long)]
    pub gui: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate shell completions
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Verify config.ini in the current directory
    CheckConfig,
    /// Sealed-key encrypt/decrypt roundtrip self-test
    Selftest {
        /// Sealed key version to test
        #[arg(default_value = "2")]
        version: u16,
    },
    /// Show SD header and key info for a save
    #[command(name = "inspect-save")]
    InspectSave {
        /// Either the sealed key (.bin) or the PFS image
        #[arg(value_name = "save")]
        save: String,
    },
    /// List files inside a save
    List {
        /// Either the sealed key (.bin) or the PFS image
        #[arg(value_name = "save")]
        save: String,
    },
    /// Decrypt a save into an editable folder of files
    Decrypt {
        /// Either the sealed key (.bin) or the PFS image
        #[arg(value_name = "save")]
        save: String,
        /// Output dir (default: decrypted/{TITLE_ID}/{name})
        #[arg(value_name = "outdir")]
        outdir: Option<String>,
    },
    /// Encrypt a directory back into a save
    Encrypt {
        #[arg(value_name = "input")]
        input: String,
        /// Output name (default: encrypted/{TITLE_ID}/{name})
        #[arg(value_name = "out")]
        out: Option<String>,
        /// EKPFS obfuscation key override (hex)
        ekpfs: Option<String>,
        /// Key seed override (hex)
        seed: Option<String>,
        /// Force total blocks (default: auto-size just enough to fit the contents)
        #[arg(long, value_name = "blocks")]
        blocks: Option<usize>,
        /// Compress files that shrink (PFSC)
        #[arg(long)]
        compress: bool,
    },
    /// Harvest the 96-byte keystone from each save as an uppercase hex dump
    Keystone {
        /// Either the sealed key (.bin) or the PFS image
        #[arg(value_name = "save")]
        save: String,
        /// Append `TITLE_ID\tkeystone_hex` lines to a file instead of stdout
        #[arg(value_name = "outfile")]
        outfile: Option<String>,
    },
    /// Decrypt, patch ACCOUNT_ID, and re-encrypt a save
    Resign {
        /// Either the sealed key (.bin) or the PFS image
        #[arg(value_name = "save")]
        save: String,
        /// New account id: bare 16-hex, 0x-hex, or decimal
        account_id: Option<String>,
        /// Output name (default: {source}_resigned)
        #[arg(value_name = "out")]
        out: Option<String>,
        /// Compress files that shrink (PFSC)
        #[arg(long)]
        compress: bool,
    },
    /// Re-region a save using a sample save from the target region
    Reregion {
        /// Source save: either the sealed key (.bin) or the PFS image
        #[arg(value_name = "src")]
        src: String,
        /// Sample save from the target region: either the sealed key (.bin) or the PFS image
        #[arg(value_name = "sample")]
        sample: String,
        /// Output name (default: {source}_reregioned)
        #[arg(value_name = "out")]
        out: Option<String>,
        /// New account id: bare 16-hex, 0x-hex, or decimal (optional)
        #[arg(long, value_name = "account_id")]
        account_id: Option<String>,
        /// Compress files that shrink (PFSC)
        #[arg(long)]
        compress: bool,
    },
}
