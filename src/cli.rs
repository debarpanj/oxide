use clap::{Parser, Subcommand};

#[derive(Parser)]
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
    },
    Delete
    {
      name: String,
    },
}



