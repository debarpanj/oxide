mod cli;

use clap::Parser;
use cli::{Cli, Commands};
mod storage;
mod crypto;
mod util;
mod totp;
fn main() {
    let cli = Cli::parse();
    match cli.command
    {
        Commands::Init => {storage::init_vault();}
        Commands::Add { name } => {let _ =util::add_entry(name);}
        Commands::List => {
            let _ = util::get_list();
        }
        Commands::Delete {name} => {let _ = util::delete_entry(name);}
        Commands::Get { name,clipboard } => {let _ = util::get_code(name,clipboard);}
    }
}
