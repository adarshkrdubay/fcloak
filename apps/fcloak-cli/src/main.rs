use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};

use fcloak_core::{
    file::{decrypt_file, encrypt_file},
    format::{ContainerFormat, detect_container_format},
    streaming_container::{decrypt_file_streaming, encrypt_file_streaming},
};

#[derive(Parser, Debug)]
#[command(name = "fcloak", version, about = "FCLOAK secure file encryption")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file into a .fcloak container.
    Encrypt {
        /// Use the streaming container format.
        #[arg(long)]
        stream: bool,

        /// Input file.
        input: PathBuf,

        /// Output .fcloak file.
        output: PathBuf,
    },

    /// Decrypt a .fcloak container.
    ///
    /// FCLOAK automatically detects whether the container
    /// uses the standard or streaming format.
    Decrypt {
        /// Input .fcloak file.
        input: PathBuf,

        /// Output decrypted file.
        output: PathBuf,
    },
}

fn read_password(confirm: bool) -> Result<String, Box<dyn std::error::Error>> {
    let password = rpassword::prompt_password("Password: ")?;

    if password.is_empty() {
        return Err("password cannot be empty".into());
    }

    if confirm {
        let confirmation = rpassword::prompt_password("Confirm password: ")?;

        if password != confirmation {
            return Err("passwords do not match".into());
        }
    }

    Ok(password)
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            stream,
            input,
            output,
        } => encrypt_command(input, output, stream),

        Commands::Decrypt { input, output } => decrypt_command(input, output),
    };

    if let Err(error) = result {
        eprintln!("FCLOAK error: {error}");
        std::process::exit(1);
    }
}

fn encrypt_command(
    input: PathBuf,
    output: PathBuf,
    stream: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !input.exists() {
        return Err(format!("input file does not exist: {}", input.display()).into());
    }

    if !input.is_file() {
        return Err(format!("input path is not a file: {}", input.display()).into());
    }

    if output.exists() {
        return Err(format!("output file already exists: {}", output.display()).into());
    }

    let password = read_password(true)?;

    println!("Encrypting: {}", input.display());

    if stream {
        println!("Mode: streaming");

        encrypt_file_streaming(&input, &output, &password)?;
    } else {
        println!("Mode: standard");

        encrypt_file(&input, &output, password.as_bytes())?;
    }

    println!("Encrypted successfully.");
    println!("Output: {}", output.display());

    Ok(())
}

fn decrypt_command(input: PathBuf, output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !input.exists() {
        return Err(format!("input file does not exist: {}", input.display()).into());
    }

    if !input.is_file() {
        return Err(format!("input path is not a file: {}", input.display()).into());
    }

    if output.exists() {
        return Err(format!("output file already exists: {}", output.display()).into());
    }

    let password = read_password(false)?;

    println!("Decrypting: {}", input.display());

    // Read the container so FCLOAK can determine
    // whether it is a standard or streaming container.
    let encoded = fs::read(&input)?;

    let container_format = detect_container_format(&encoded)
        .map_err(|_| "invalid or unsupported FCLOAK container format")?;

    match container_format {
        ContainerFormat::Standard => {
            println!("Mode: standard");

            decrypt_file(&input, &output, password.as_bytes())?;
        }

        ContainerFormat::Streaming => {
            println!("Mode: streaming");

            decrypt_file_streaming(&input, &output, &password)?;
        }
    }

    println!("Decrypted successfully.");
    println!("Output: {}", output.display());

    Ok(())
}
