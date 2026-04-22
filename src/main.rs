mod cli;

use clap::Parser;
use cli::{Cli, Commands};
mod storage;
mod crypto;
fn main() {
    let cli = Cli::parse();
    match cli.command
    {
        Commands::Init => {crate::storage::init_vault();}
        Commands::Add { name } => {println!("{}",name);}
        Commands::List => { println!("list");}
        Commands::Delete {name} => {println!("{}",name);}
    }
}
