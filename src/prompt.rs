use std::io::Write;
use std::io::{self};

use anyhow::Result;
use anyhow::bail;

pub fn ask_text(label: &str, default: Option<&str>) -> Result<String> {
    loop {
        match default {
            Some(value) if !value.is_empty() => print!("{label} [{value}]: "),
            _ => print!("{label}: "),
        }
        io::stdout().flush()?;

        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let input = buf.trim();

        if input.eq_ignore_ascii_case("cancel") {
            bail!("cancelled by user")
        }

        if input.is_empty() {
            if let Some(value) = default {
                return Ok(value.to_string());
            }
            println!("Please enter a value, or type 'cancel'.");
            continue;
        }

        return Ok(input.to_string());
    }
}

pub fn ask_yes_no(label: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        print!("{label} {suffix}: ");
        io::stdout().flush()?;

        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let input = buf.trim().to_ascii_lowercase();

        if input.is_empty() {
            return Ok(default_yes);
        }

        match input.as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            "cancel" => bail!("cancelled by user"),
            _ => println!("Please answer yes or no, or type 'cancel'."),
        }
    }
}

pub fn select_one(label: &str, items: &[String]) -> Result<String> {
    if items.is_empty() {
        bail!("no selectable items available for {label}")
    }

    println!("{label}:");
    for (index, item) in items.iter().enumerate() {
        println!("  {}) {}", index + 1, item);
    }

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let input = buf.trim();

        if input.eq_ignore_ascii_case("cancel") {
            bail!("cancelled by user")
        }

        if let Ok(index) = input.parse::<usize>() {
            if index >= 1 && index <= items.len() {
                return Ok(items[index - 1].clone());
            }
        }

        if let Some(item) = items.iter().find(|item| item.as_str() == input) {
            return Ok(item.clone());
        }

        println!("Choose an item by number or exact name, or type 'cancel'.");
    }
}
