use crate::crypto;
use crate::util::set_master_password;
use ::std::fs;
use colored::*;
use rusqlite::{Connection, Error as SqliteError, OptionalExtension, params};
use std::path::PathBuf;

pub struct Vault {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn get_vault_from_db(connection: &Connection) -> Result<Vault, String> {
    connection
        .query_row(
            "SELECT salt, nonce, ciphertext
        FROM vault_metadata WHERE id = 1",
            [],
            |row| {
                Ok(Vault {
                    salt: row.get(0)?,
                    nonce: row.get(1)?,
                    ciphertext: row.get(2)?,
                })
            },
        )
        .map_err(|e| match e {
            SqliteError::QueryReturnedNoRows => {
                "Vault database is incomplete: missing vault metadata. Delete ~/.oxide/vault.db and run `oxide init` again."
                    .to_string()
            }
            _ => format!("Failed to read vault metadata: {}", e),
        })
}

pub fn get_names_from_db(connection: &Connection) -> Result<Vec<String>, String> {
    let mut stmt = connection
        .prepare(
            "
   SELECT name FROM entries ORDER BY name ASC",
        )
        .map_err(|e| format!("Failed to prepare account list query: {}", e))?;
    let mut names = Vec::new();
    let name_iter = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| format!("Failed to query account list: {}", e))?;

    for name in name_iter {
        names.push(name.map_err(|e| format!("Failed to read account name: {}", e))?);
    }
    Ok(names)
}

pub fn get_entry_by_name(
    name: &String,
    connection: &Connection,
) -> Result<Option<(String, String)>, String> {
    let mut stmt = connection
        .prepare(
            "
    SELECT nonce, ciphertext FROM entries WHERE name= ?1",
        )
        .map_err(|e| format!("Failed to prepare account lookup: {}", e))?;

    stmt.query_row(params![name], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()
        .map_err(|e| format!("Failed to read account {}: {}", name, e))
}

fn setup_db(path: &PathBuf) -> Result<Connection, String> {
    let connection =
        Connection::open(path).map_err(|e| format!("Failed to open vault database: {}", e))?;
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version TEXT NOT NULL,
    salt TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL
);",
            (),
        )
        .map_err(|e| format!("Failed to create vault_metadata table: {}", e))?;
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS entries (
    name TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL
);",
            (),
        )
        .map_err(|e| format!("Failed to create entries table: {}", e))?;
    Ok(connection)
}

pub fn get_db_path() -> Result<PathBuf, String> {
    let mut home_path = home::home_dir().ok_or("Could not find home directory!!!".to_string())?;
    home_path.push(".oxide");
    home_path.push("vault");
    home_path.set_extension("db");
    Ok(home_path)
}

fn get_temp_db_path(db_path: &PathBuf) -> PathBuf {
    let mut temp_path = db_path.clone();
    temp_path.set_extension("db.tmp");
    temp_path
}

pub fn get_db_connection() -> Result<Connection, String> {
    let db_path = get_db_path()?;
    if !fs::exists(&db_path).map_err(|e| format!("Cannot access the vault database: {}", e))? {
        return Err("Vault database does not exist. Run `oxide init` first.".to_string());
    }
    Connection::open(db_path).map_err(|e| format!("Failed to open vault database: {}", e))
}

pub fn init_vault() -> Result<(), String> {
    let db_file_path = get_db_path()?;
    let db_directory_path = db_file_path
        .parent()
        .ok_or("Cannot get parent directory!!!".to_string())?;
    if !fs::exists(db_directory_path).map_err(|e| format!("Cannot access the folder: {}", e))? {
        fs::create_dir(db_directory_path)
            .map_err(|e| format!("Cannot create vault directory: {}", e))?;
        init_vault_file(&db_file_path)?;
    } else if !fs::exists(&db_file_path).map_err(|e| format!("Cannot access the file: {}", e))? {
        init_vault_file(&db_file_path)?;
    } else {
        println!("{}", "Vault file already exists!!!".red().bold());
        println!("{}", "Cannot Init!!!".red().bold());
    }
    Ok(())
}

fn init_vault_file(db_path: &PathBuf) -> Result<(), String> {
    let temp_db_path = get_temp_db_path(db_path);
    if fs::exists(&temp_db_path).map_err(|e| format!("Cannot access temp vault database: {}", e))? {
        fs::remove_file(&temp_db_path)
            .map_err(|e| format!("Cannot remove incomplete temp vault database: {}", e))?;
    }

    let password = set_master_password()?;
    let plain_text = String::from("*** God Is Good ***");
    let salt = crypto::get_salt();
    let key = crypto::derive_key(&password, &salt)?;
    let (cipher_text, nonce) = crypto::encrypt(&plain_text, key)?;

    let result = (|| {
        let connection = setup_db(&temp_db_path)?;
        connection
            .execute(
                "INSERT INTO vault_metadata (id, version, salt, nonce, ciphertext) 
         VALUES (1, ?1, ?2, ?3, ?4)",
                params!["1.0.0", salt.as_str(), nonce.as_str(), cipher_text.as_str()],
            )
            .map_err(|e| format!("Failed to initialize vault metadata: {}", e))?;
        drop(connection);

        if fs::exists(db_path).map_err(|e| format!("Cannot access the vault database: {}", e))? {
            return Err("Vault file already exists!!! Cannot Init!!!".to_string());
        }

        fs::rename(&temp_db_path, db_path)
            .map_err(|e| format!("Failed to finalize vault database: {}", e))?;
        Ok(())
    })();

    if result.is_err() && fs::exists(&temp_db_path).unwrap_or(false) {
        let _ = fs::remove_file(&temp_db_path);
    }

    result
}
