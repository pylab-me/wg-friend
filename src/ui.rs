use std::env;
use std::io::{
    IsTerminal, {self},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tone {
    Info,
    Good,
    Warn,
    Bad,
    Accent,
    Muted,
}

#[derive(Clone, Debug)]
pub struct KvRow {
    pub key: String,
    pub value: String,
}

impl KvRow {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: Vec<String>) -> Self {
        Self {
            headers,
            rows: Vec::new(),
        }
    }

    pub fn push_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn render(&self) -> String {
        if self.headers.is_empty() {
            return String::new();
        }

        let cols = self.headers.len();
        let mut widths = self.headers.iter().map(|item| display_width(item)).collect::<Vec<_>>();

        for row in &self.rows {
            for (idx, cell) in row.iter().enumerate().take(cols) {
                widths[idx] = widths[idx].max(display_width(cell));
            }
        }

        let header = self
            .headers
            .iter()
            .enumerate()
            .map(|(idx, cell)| pad_right(cell, widths[idx]))
            .collect::<Vec<_>>()
            .join("  ");

        let mut out = String::new();
        out.push_str(&paint(&header, Tone::Accent, true));
        out.push('\n');
        out.push_str(&widths.iter().map(|width| "-".repeat(*width)).collect::<Vec<_>>().join("  "));

        for row in &self.rows {
            out.push('\n');
            let line = (0..cols)
                .map(|idx| {
                    let value = row.get(idx).cloned().unwrap_or_default();
                    pad_right(&value, widths[idx])
                })
                .collect::<Vec<_>>()
                .join("  ");
            out.push_str(&line);
        }

        out
    }
}

pub fn kv(key: impl Into<String>, value: impl Into<String>) -> KvRow {
    KvRow::new(key, value)
}

pub fn print_section(title: &str) {
    println!();
    println!("{}", section_title(title));
    println!("{}", divider(64));
}

pub fn print_kv_rows(rows: &[KvRow]) {
    let rendered = render_kv_rows(rows);
    if !rendered.is_empty() {
        println!("{rendered}");
    }
}

pub fn render_kv_rows(rows: &[KvRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let key_width = rows.iter().map(|row| display_width(&row.key)).max().unwrap_or(0);
    rows.iter()
        .map(|row| format!("{}  {}", pad_right(&row.key, key_width), row.value))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn print_table(table: &Table) {
    if !table.is_empty() {
        println!("{}", table.render());
    }
}

pub fn print_block(text: &str) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        println!("{}", paint("<empty>", Tone::Muted, false));
        return;
    }

    for line in trimmed.lines() {
        println!("  {line}");
    }
}

pub fn print_message(text: &str, tone: Tone) {
    println!("{}", paint(text, tone, false));
}

pub fn section_title(title: &str) -> String {
    paint(title, Tone::Accent, true)
}

pub fn divider(width: usize) -> String {
    let count = width.max(12);
    paint(&"─".repeat(count), Tone::Muted, false)
}

pub fn badge(text: &str, tone: Tone) -> String {
    paint(text, tone, true)
}

pub fn status_badge(text: &str) -> String {
    let normalized = text.trim().to_ascii_lowercase();
    let tone = match normalized.as_str() {
        "active" | "enabled" | "up" | "running" | "ready" | "ok" | "yes" | "present"
        | "started" | "restarted" | "online" => Tone::Good,
        "inactive" | "disabled" | "down" | "failed" | "error" | "no" | "missing" | "stopped"
        | "offline" => Tone::Bad,
        "unknown" | "degraded" | "partial" | "warning" | "probing" | "stale" => Tone::Warn,
        _ => Tone::Info,
    };
    badge(text, tone)
}

pub fn yes_no(value: bool) -> String {
    if value {
        status_badge("yes")
    } else {
        status_badge("no")
    }
}

pub fn truncate_middle(value: &str, max_len: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= max_len || max_len <= 5 {
        return value.to_string();
    }

    let left = (max_len.saturating_sub(1)) / 2;
    let right = max_len.saturating_sub(left + 1);
    let start = chars.iter().take(left).collect::<String>();
    let end = chars.iter().rev().take(right).rev().collect::<String>();
    format!("{start}…{end}")
}

fn pad_right(value: &str, width: usize) -> String {
    let pad = width.saturating_sub(display_width(value));
    format!("{value}{}", " ".repeat(pad))
}

fn display_width(value: &str) -> usize {
    strip_ansi(value).chars().count()
}

fn strip_ansi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if matches!(chars.peek(), Some(&'[')) {
                chars.next();
                while let Some(next) = chars.next() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(ch);
    }
    out
}

fn paint(value: &str, tone: Tone, bold: bool) -> String {
    if !colors_enabled() {
        return value.to_string();
    }

    let code = match tone {
        Tone::Info => "36",
        Tone::Good => "32",
        Tone::Warn => "33",
        Tone::Bad => "31",
        Tone::Accent => "35",
        Tone::Muted => "90",
    };

    if bold {
        format!("\x1b[1;{code}m{value}\x1b[0m")
    } else {
        format!("\x1b[{code}m{value}\x1b[0m")
    }
}

fn colors_enabled() -> bool {
    if env::var_os("NO_COLOR").is_some() {
        return false;
    }

    if let Some(value) = env::var_os("CLICOLOR_FORCE") {
        if value.to_string_lossy() != "0" {
            return true;
        }
    }

    io::stdout().is_terminal() && env::var_os("TERM").is_some()
}
