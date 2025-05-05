use clap::Parser;
use color_eyre::eyre::Result;
use onionb::parse_input;
use std::path::PathBuf;

#[derive(Parser)]
struct CliArgs {
    #[command()]
    output_directory: PathBuf,
    #[command()]
    input_file: PathBuf,
}
fn main() -> Result<()> {
    color_eyre::install()?;
    let args = CliArgs::parse();
    let input = std::fs::read(args.input_file)?;
    let mut inp = parse_input(input)?;
    let mut ans = inp.get_onion_hex()?;
    ans.push('\n'); // AS output.txt has a new line
    std::fs::write(args.output_directory.join("output.txt"), ans)?;

    Ok(())
}
