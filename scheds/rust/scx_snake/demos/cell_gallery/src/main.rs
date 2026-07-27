// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::fs;
use std::hint::spin_loop;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle, Thread};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use scx_snake_cell_gallery::{
    build_gallery, render_policy, validate_canvas_affinity, validate_canvas_cpus, Gallery,
    GalleryCell, Playback, CANVAS_CPUS,
};
use scx_stats::StatsClient;
use scx_utils::Topology;
use serde::Deserialize;

const CONTROL_TIMEOUT_MS: u64 = 15_000;
const WORKER_STACK_BYTES: usize = 128 * 1024;
const WORKER_START_TIMEOUT: Duration = Duration::from_secs(30);
const WORKER_BURST: Duration = Duration::from_micros(50);
const INTERRUPT_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Parser)]
#[command(
    name = "scx_snake_cell_gallery",
    about = "Draw fixed-cell pixel art in the Snake inspector"
)]
struct Args {
    /// Seconds to display each image before activating the next cohort.
    #[arg(long, default_value = "10", value_parser = parse_positive_seconds)]
    interval: Duration,

    /// Complete gallery loops before exiting; zero loops forever.
    #[arg(long, default_value_t = 0)]
    cycles: u32,

    /// Policy restored after the gallery exits.
    #[arg(long, value_name = "PATH")]
    restore_policy: Option<PathBuf>,

    /// Snake statistics/control socket.
    #[arg(long, default_value = "/var/run/scx/root/stats", value_name = "PATH")]
    stats_socket: PathBuf,

    /// Begin playback without waiting for inspector scope setup.
    #[arg(long)]
    start_immediately: bool,

    /// Print the generated static policy and exit.
    #[arg(long)]
    dump_policy: bool,
}

fn parse_positive_seconds(value: &str) -> std::result::Result<Duration, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|error| format!("invalid interval `{value}`: {error}"))?;
    if seconds == 0 {
        return Err("interval must be greater than zero".into());
    }
    Ok(Duration::from_secs(seconds))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let gallery = build_gallery()?;
    if args.dump_policy {
        print!("{}", render_policy(&gallery));
        return Ok(());
    }
    let restore_path = args
        .restore_policy
        .as_deref()
        .context("--restore-policy is required for live gallery execution")?;

    let topology = Topology::new().context("discovering CPUs for the cell-art canvas")?;
    let cpus = topology
        .all_cpus
        .keys()
        .map(|&cpu| u32::try_from(cpu).context("CPU ID does not fit u32"))
        .collect::<Result<Vec<_>>>()?;
    validate_canvas_cpus(&cpus)?;
    validate_canvas_affinity(&process_affinity()?)?;

    let restore_source = read_policy(restore_path)?;
    run_gallery(&args, gallery, restore_source)
}

#[derive(Debug, Deserialize)]
struct PolicyUpdateResponse {
    generation: u64,
    rung_count: usize,
    mask_table_count: usize,
    summary: String,
}

#[derive(Debug, Deserialize)]
struct ThreadCellResponse {
    tid: i32,
    cell_id: Option<u32>,
    rehome_requested: bool,
}

struct Worker {
    cell: GalleryCell,
    tid: i32,
    thread: Thread,
    join: JoinHandle<()>,
}

fn read_policy(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("reading restore policy {}", path.display()))
}

fn process_affinity() -> Result<Vec<u32>> {
    // SAFETY: An all-zero cpu_set_t is a valid output buffer for sched_getaffinity.
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    // SAFETY: set points to a writable cpu_set_t with the supplied exact size.
    if unsafe {
        libc::sched_getaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            std::ptr::addr_of_mut!(set),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("reading gallery process affinity");
    }

    Ok((0..CANVAS_CPUS)
        .filter(|&cpu| {
            // SAFETY: Gallery CPU IDs are below libc::CPU_SETSIZE.
            unsafe { libc::CPU_ISSET(cpu as usize, &set) }
        })
        .collect())
}

fn run_gallery(args: &Args, gallery: Gallery, restore_source: String) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let active_image = Arc::new(AtomicUsize::new(usize::MAX));
    install_signal_handler(Arc::clone(&shutdown))?;

    let mut client = StatsClient::new()
        .set_path(&args.stats_socket)
        .connect(Some(CONTROL_TIMEOUT_MS))
        .with_context(|| format!("connecting to {}", args.stats_socket.display()))?;
    let gallery_source = render_policy(&gallery);
    let activated = match request_policy_update(&mut client, &gallery_source) {
        Ok(response) => response,
        Err(error) => {
            return finish_with_restore(
                Err(error.context("activating cell-art gallery policy")),
                &mut client,
                &restore_source,
            );
        }
    };
    println!(
        "activated gallery policy generation {} ({})",
        activated.generation, activated.summary
    );
    let session_result = if activated.rung_count != 1 || activated.mask_table_count != 1 {
        Err(anyhow::anyhow!(
            "gallery policy activated with {} rungs and {} mask tables",
            activated.rung_count,
            activated.mask_table_count
        ))
    } else {
        match spawn_workers(&gallery, Arc::clone(&active_image), Arc::clone(&shutdown)) {
            Err(error) => Err(error),
            Ok(workers) => {
                let playback_result = (|| -> Result<()> {
                    assign_workers(&mut client, &workers, &shutdown)?;
                    println!(
                        "mapped {} worker threads once across {} fixed image cells",
                        workers.len(),
                        gallery.cells.len()
                    );
                    if !args.start_immediately {
                        wait_for_inspector(&shutdown)?;
                    }
                    play(
                        &gallery,
                        &workers,
                        args.interval,
                        args.cycles,
                        &active_image,
                        &shutdown,
                    )
                })();

                shutdown.store(true, Ordering::Relaxed);
                for worker in &workers {
                    worker.thread.unpark();
                }
                let join_result = join_workers(workers);
                playback_result.and(join_result)
            }
        }
    };

    finish_with_restore(session_result, &mut client, &restore_source)
}

fn install_signal_handler(shutdown: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || shutdown.store(true, Ordering::Relaxed))
        .context("installing gallery signal handler")
}

fn request_policy_update(client: &mut StatsClient, source: &str) -> Result<PolicyUpdateResponse> {
    client
        .request(
            "stats",
            vec![
                ("target".into(), "policy_update".into()),
                ("source".into(), source.into()),
            ],
        )
        .context("updating scheduler policy")
}

fn finish_with_restore<T>(
    result: Result<T>,
    client: &mut StatsClient,
    restore_source: &str,
) -> Result<T> {
    let restore_result = request_policy_update(client, restore_source)
        .map(|response| {
            println!("restored policy generation {}", response.generation);
        })
        .context("restoring scheduler policy");

    match (result, restore_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(restore_error)) => Err(error.context(format!(
            "restoring the scheduler policy also failed: {restore_error:#}"
        ))),
    }
}

fn assign_workers(
    client: &mut StatsClient,
    workers: &[Worker],
    shutdown: &AtomicBool,
) -> Result<()> {
    for worker in workers {
        if shutdown.load(Ordering::Relaxed) {
            bail!("gallery interrupted while assigning workers");
        }
        let tid = worker.tid;
        let response: ThreadCellResponse = client
            .request(
                "stats",
                vec![
                    ("target".into(), "thread_cell_set".into()),
                    ("tid".into(), tid.to_string()),
                    ("cell_id".into(), worker.cell.id.to_string()),
                ],
            )
            .with_context(|| format!("assigning TID {tid} to cell {}", worker.cell.id))?;
        if response.tid != tid
            || response.cell_id != Some(worker.cell.id)
            || !response.rehome_requested
        {
            bail!(
                "unexpected assignment response for TID {tid}, cell {}: {response:?}",
                worker.cell.id
            );
        }
    }
    Ok(())
}

fn spawn_workers(
    gallery: &Gallery,
    active_image: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
) -> Result<Vec<Worker>> {
    let (tids, tid_rx) = mpsc::channel();
    let mut pending = Vec::with_capacity(gallery.cells.len());
    for cell in &gallery.cells {
        let cell = cell.clone();
        let worker_cell = cell.clone();
        let worker_active_image = Arc::clone(&active_image);
        let worker_shutdown = Arc::clone(&shutdown);
        let tids = tids.clone();
        let join = match thread::Builder::new()
            .stack_size(WORKER_STACK_BYTES)
            .spawn(move || {
                let tid = current_tid();
                let _ = tids.send((worker_cell.id, tid, thread::current()));
                worker_loop(&worker_cell, &worker_active_image, &worker_shutdown);
            }) {
            Ok(join) => join,
            Err(error) => {
                stop_pending_workers(pending, &shutdown);
                return Err(error).with_context(|| format!("spawning worker for cell {}", cell.id));
            }
        };
        pending.push((cell, join));
    }
    drop(tids);

    let deadline = Instant::now() + WORKER_START_TIMEOUT;
    let mut identities = BTreeMap::new();
    for _ in 0..pending.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (cell_id, tid, worker_thread) = match tid_rx.recv_timeout(remaining) {
            Ok(identity) => identity,
            Err(error) => {
                stop_pending_workers(pending, &shutdown);
                return Err(error).context("timed out waiting for gallery worker TIDs");
            }
        };
        identities.insert(cell_id, (tid, worker_thread));
    }

    if identities.len() != pending.len()
        || pending
            .iter()
            .any(|(cell, _)| !identities.contains_key(&cell.id))
    {
        stop_pending_workers(pending, &shutdown);
        bail!("gallery workers reported duplicate or unknown cell identities");
    }

    Ok(pending
        .into_iter()
        .map(|(cell, join)| {
            let (tid, worker_thread) = identities
                .remove(&cell.id)
                .expect("worker identities were validated");
            Worker {
                cell,
                tid,
                thread: worker_thread,
                join,
            }
        })
        .collect())
}

fn stop_pending_workers(pending: Vec<(GalleryCell, JoinHandle<()>)>, shutdown: &AtomicBool) {
    shutdown.store(true, Ordering::Relaxed);
    for (_, join) in &pending {
        join.thread().unpark();
    }
    for (_, join) in pending {
        let _ = join.join();
    }
}

fn current_tid() -> i32 {
    // Linux thread IDs use pid_t even though syscall returns a machine word.
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn worker_loop(cell: &GalleryCell, active_image: &AtomicUsize, shutdown: &AtomicBool) {
    let mut random = u64::from(cell.id).wrapping_add(1);
    while !shutdown.load(Ordering::Relaxed) {
        let image = active_image.load(Ordering::Relaxed);
        if !cell.is_active_for(image) {
            thread::park();
            continue;
        }

        let until = Instant::now() + WORKER_BURST;
        while Instant::now() < until {
            spin_loop();
        }
        random = random
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        thread::sleep(Duration::from_millis(20 + random % 21));
    }
}

fn wait_for_inspector(shutdown: &Arc<AtomicBool>) -> Result<()> {
    println!("gallery TGID: {}", std::process::id());
    println!("in the inspector select: TGID above, Numeric order, 10 s window");
    print!("press Enter to begin the automatic gallery: ");
    io::stdout().flush()?;

    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = io::stdin().read_line(&mut line);
        let _ = ready_tx.send(result);
    });
    loop {
        if shutdown.load(Ordering::Relaxed) {
            bail!("gallery interrupted before playback")
        }
        match ready_rx.recv_timeout(INTERRUPT_POLL) {
            Ok(result) => return result.map(|_| ()).context("reading gallery start prompt"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("gallery start prompt disconnected")
            }
        }
    }
}

fn play(
    gallery: &Gallery,
    workers: &[Worker],
    interval: Duration,
    cycles: u32,
    active_image: &AtomicUsize,
    shutdown: &AtomicBool,
) -> Result<()> {
    for image_index in Playback::new(gallery.images.len(), cycles)? {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let image = &gallery.images[image_index];
        active_image.store(image_index, Ordering::Relaxed);
        for worker in workers {
            if worker.cell.is_active_for(image_index) {
                worker.thread.unpark();
            }
        }
        println!(
            "showing {} ({} fixed cells)",
            image.name,
            image.cell_ids.len()
        );
        sleep_interruptibly(interval, shutdown);
    }
    active_image.store(usize::MAX, Ordering::Relaxed);
    Ok(())
}

fn sleep_interruptibly(duration: Duration, shutdown: &AtomicBool) {
    let deadline = Instant::now() + duration;
    while !shutdown.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::sleep((deadline - now).min(INTERRUPT_POLL));
    }
}

fn join_workers(workers: Vec<Worker>) -> Result<()> {
    for worker in workers {
        worker
            .join
            .join()
            .map_err(|_| anyhow::anyhow!("gallery worker for cell {} panicked", worker.cell.id))?;
    }
    Ok(())
}
