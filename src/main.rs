mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use colored::*;
mod crypto;
mod storage;
mod totp;
mod util;

fn print_error(error: String) {
    println!("{}", error.red().bold());
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            util::print_banner();
            if let Err(error) = storage::init_vault() {
                print_error(error);
            }
        }
        Commands::Add { name } => {
            if let Err(error) = util::add_entry(name) {
                print_error(error);
            }
        }
        Commands::List => {
            if let Err(error) = util::get_list() {
                print_error(error);
            }
        }
        Commands::Delete { name } => {
            if let Err(error) = util::delete_entry(name) {
                print_error(error);
            }
        }
        Commands::Get { name, clipboard } => {
            util::print_banner();
            if let Err(error) = util::get_code(name, clipboard) {
                print_error(error);
            }
        }
    }
}
