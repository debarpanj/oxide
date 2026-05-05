use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "oxide")]
#[command(about = "A secure CLI TOTP vault", long_about = None)]
pub struct Cli
{
  #[command(subcommand)]
  pub command: Commands
}

#[derive(Subcommand)]
pub enum Commands
{
    Init,
    Add
    {
        name: String,
    },
    List,
    Get {
        name: String,
        #[arg(short, long)]
        clipboard: bool,
    },
    Delete
    {
      name: String,
    },
}



