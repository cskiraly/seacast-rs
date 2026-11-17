//! Prints the heap a `SeacastNode` holds after `new`, for the default
//! capacities and for larger peer counts. The handle is `Vec<u8>`: a table of
//! handles scales with the host's handle size.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use seacast_core::{NodeConfig, SeacastNode};

struct Counting;

const TOP: usize = 12;

static TRACK: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static SIZES: [AtomicUsize; 16384] = [const { AtomicUsize::new(0) }; 16384];

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            let at = COUNT.fetch_add(1, Ordering::Relaxed);
            if at < SIZES.len() {
                SIZES[at].store(layout.size(), Ordering::Relaxed);
            }
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACK.load(Ordering::Relaxed) {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn measure(max_peers: usize) {
    let mut config = NodeConfig::default();
    config.capacities.max_peers = max_peers;

    LIVE.store(0, Ordering::Relaxed);
    COUNT.store(0, Ordering::Relaxed);
    TRACK.store(true, Ordering::Relaxed);
    let node = SeacastNode::<Vec<u8>>::new(config);
    TRACK.store(false, Ordering::Relaxed);

    let (live, count) = (LIVE.load(Ordering::Relaxed), COUNT.load(Ordering::Relaxed));
    // Equal sizes together, the largest sum first: a table made once per peer shows
    // as one line.
    let mut sizes: Vec<usize> =
        SIZES[..count.min(SIZES.len())].iter().map(|s| s.load(Ordering::Relaxed)).collect();
    sizes.sort_unstable();
    let mut groups: Vec<(usize, usize)> = Vec::new();
    for size in sizes {
        match groups.last_mut() {
            Some((of, n)) if *of == size => *n += 1,
            _ => groups.push((size, 1)),
        }
    }
    groups.sort_unstable_by_key(|&(size, n)| std::cmp::Reverse(size * n));
    groups.truncate(TOP);

    println!(
        "max_peers {max_peers:5}: heap {:8.2} MiB in {count} allocations, struct {} bytes",
        live as f64 / (1 << 20) as f64,
        std::mem::size_of_val(&node),
    );
    for (size, n) in groups {
        println!("  {:8.2} MiB = {n} x {size} bytes", (size * n) as f64 / (1 << 20) as f64);
    }
    drop(node);
}

fn main() {
    for max_peers in [64, 256, 1024] {
        measure(max_peers);
    }
}
