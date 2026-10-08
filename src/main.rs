use anyhow::Result;
use clap::Parser;
use comfy_table::{Cell, Table};
use std::time::Instant;

mod cli;
mod csum;
mod db;
mod dedupe;
mod protocol;

use dedupe::{DedupeConfig, DedupeSession};

fn setup_logging() {
    use std::fs::OpenOptions;
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("dduper.log")
        .ok();

    let mut builder = env_logger::Builder::new();
    builder.filter_level(log::LevelFilter::Debug);

    if let Some(file) = log_file {
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    }

    builder.init();
}

fn main() -> Result<()> {
    setup_logging();

    let opts = cli::Opts::parse();
    let start = Instant::now();
    csum::get_ele_size(opts.chunk_size)?;
    if opts.fast_mode {
        anyhow::bail!(
            "--fast-mode is disabled: use the default kernel-verified FIDEDUPERANGE mode"
        );
    }

    // Open database
    let db = db::CsumDb::open(std::path::Path::new("dduper.db"))?;

    if opts.analyze {
        run_analyze(&opts, db)?;
    } else {
        run_normal(&opts, db)?;
    }

    let duration = start.elapsed();
    println!("dduper took {:.2} seconds", duration.as_secs_f64());

    Ok(())
}

fn run_analyze(opts: &cli::Opts, db: db::CsumDb) -> Result<()> {
    let chunk_sizes = [128u64, 256, 512, 1024, 2048, 4096, 8192, 16384];
    let mut session = DedupeSession::new(db);

    for &sz in &chunk_sizes {
        let config = DedupeConfig {
            device: opts.device.clone(),
            dry_run: true, // analyze implies dry_run
            verbose: opts.verbose,
            analyze: true,
            perfect_match_only: opts.perfect_match_only,
            recurse: opts.recurse,
            chunk_sz: sz,
        };

        if !opts.files.is_empty() {
            dedupe::dedupe_files(&opts.files, &config, &mut session)?;
        } else if !opts.dir_path.is_empty() {
            dedupe::dedupe_dir(&opts.dir_path, &config, &mut session)?;
        }

        // Clear processed files between chunk-size iterations (matches Python)
        session.processed_files.clear();
    }

    // Print analyze results
    print_analysis_results(&session);

    Ok(())
}

fn run_normal(opts: &cli::Opts, db: db::CsumDb) -> Result<()> {
    let config = DedupeConfig {
        device: opts.device.clone(),
        dry_run: opts.dry_run || opts.perfect_match_only,
        verbose: opts.verbose,
        analyze: false,
        perfect_match_only: opts.perfect_match_only,
        recurse: opts.recurse,
        chunk_sz: opts.chunk_size,
    };

    let mut session = DedupeSession::new(db);

    if opts.perfect_match_only {
        println!("Find duplicate files...");
    }

    if !opts.files.is_empty() {
        dedupe::dedupe_files(&opts.files, &config, &mut session)?;
    } else if !opts.dir_path.is_empty() {
        dedupe::dedupe_dir(&opts.dir_path, &config, &mut session)?;
    } else {
        eprintln!("No files or directories specified");
        std::process::exit(1);
    }

    Ok(())
}

fn print_analysis_results(session: &DedupeSession) {
    for (chunk_sz, entries) in &session.analyze_results {
        let mut table = Table::new();
        table.set_header(vec![
            Cell::new("Chunk Size(KB)"),
            Cell::new("Files"),
            Cell::new("Duplicate(KB)"),
        ]);

        let mut total_sz = 0u64;
        for entry in entries {
            table.add_row(vec![
                Cell::new(chunk_sz),
                Cell::new(&entry.files),
                Cell::new(entry.duplicate_kb),
            ]);
            total_sz += entry.duplicate_kb;
        }

        println!("{table}");
        println!(
            "dduper:{}KB of duplicate data found with chunk size:{}KB\n",
            total_sz, chunk_sz
        );
    }
}
