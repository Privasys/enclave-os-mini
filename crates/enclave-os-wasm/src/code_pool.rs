// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Page bookkeeping for the executable code pool.
//!
//! The pool is a fixed run of pages (the RWX `.wasm_code` section, see
//! `sgx_platform`). [`PagePool`] decides which pages each allocation gets and
//! takes them back when the allocation is freed, so loading, unloading,
//! evicting and redeploying apps reuses the same pages instead of using the
//! pool up.
//!
//! It only deals in page indices and never touches memory, so it runs, and is
//! tested, on the host (`tests/code-pool-unit`).

use std::vec::Vec;

/// Why [`PagePool::free`] refused a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeError {
    /// No allocation starts at this page.
    NotAllocated,
    /// An allocation starts here, but with a different page count.
    SizeMismatch {
        /// Pages the allocation holds.
        allocated: usize,
    },
}

/// First-fit page allocator over `total` pages.
///
/// Allocations are kept sorted by first page; the free space is the gaps
/// between them, so freeing an allocation merges its pages with any free
/// neighbours without extra work. An allocation is freed whole, by its first
/// page and page count, which is how wasmtime unmaps (the full mapping on
/// drop).
#[derive(Debug)]
pub struct PagePool {
    total: usize,
    /// `(first page, page count)`, sorted by first page, non-overlapping.
    allocations: Vec<(usize, usize)>,
    in_use: usize,
    peak: usize,
}

impl PagePool {
    /// An empty pool of `total` pages.
    pub const fn new(total: usize) -> Self {
        Self {
            total,
            allocations: Vec::new(),
            in_use: 0,
            peak: 0,
        }
    }

    /// Take `pages` contiguous pages, returning the first one, or `None` if
    /// no free run is long enough (or `pages` is 0).
    pub fn alloc(&mut self, pages: usize) -> Option<usize> {
        if pages == 0 || pages > self.total - self.in_use {
            return None;
        }
        let mut cursor = 0;
        let mut slot = self.allocations.len();
        for (i, &(first, count)) in self.allocations.iter().enumerate() {
            if first - cursor >= pages {
                slot = i;
                break;
            }
            cursor = first + count;
        }
        if slot == self.allocations.len() && self.total - cursor < pages {
            return None;
        }
        self.allocations.insert(slot, (cursor, pages));
        self.in_use += pages;
        self.peak = self.peak.max(self.in_use);
        Some(cursor)
    }

    /// Give back the allocation that starts at `first` and holds `pages`.
    ///
    /// A range that is not exactly one allocation is refused and nothing is
    /// freed: freeing the wrong pages could hand out code that is still in
    /// use.
    pub fn free(&mut self, first: usize, pages: usize) -> Result<(), FreeError> {
        let i = self
            .allocations
            .binary_search_by_key(&first, |&(f, _)| f)
            .map_err(|_| FreeError::NotAllocated)?;
        let allocated = self.allocations[i].1;
        if allocated != pages {
            return Err(FreeError::SizeMismatch { allocated });
        }
        self.allocations.remove(i);
        self.in_use -= pages;
        Ok(())
    }

    /// Whether `pages` pages starting at `first` all lie inside one
    /// allocation.
    pub fn is_allocated(&self, first: usize, pages: usize) -> bool {
        let i = match self.allocations.binary_search_by_key(&first, |&(f, _)| f) {
            Ok(i) => i,
            Err(0) => return false,
            Err(i) => i - 1,
        };
        let (start, count) = self.allocations[i];
        first >= start && first + pages <= start + count
    }

    /// Pool size in pages.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Pages currently allocated.
    pub fn in_use(&self) -> usize {
        self.in_use
    }

    /// Most pages ever allocated at once.
    pub fn peak(&self) -> usize {
        self.peak
    }

    /// Number of live allocations.
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// The longest free run, in pages: the largest allocation that would
    /// succeed right now.
    pub fn largest_free_run(&self) -> usize {
        let mut cursor = 0;
        let mut best = 0;
        for &(first, count) in &self.allocations {
            best = best.max(first - cursor);
            cursor = first + count;
        }
        best.max(self.total - cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_first_fit_from_the_start() {
        let mut pool = PagePool::new(16);
        assert_eq!(pool.alloc(4), Some(0));
        assert_eq!(pool.alloc(4), Some(4));
        assert_eq!(pool.alloc(8), Some(8));
        assert_eq!(pool.in_use(), 16);
        assert_eq!(pool.alloc(1), None);
        assert_eq!(pool.largest_free_run(), 0);
    }

    #[test]
    fn zero_or_oversized_requests_fail() {
        let mut pool = PagePool::new(8);
        assert_eq!(pool.alloc(0), None);
        assert_eq!(pool.alloc(9), None);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn freed_pages_are_reused() {
        let mut pool = PagePool::new(8);
        let a = pool.alloc(8).unwrap();
        assert_eq!(pool.alloc(1), None);
        pool.free(a, 8).unwrap();
        assert_eq!(pool.in_use(), 0);
        assert_eq!(pool.alloc(8), Some(0));
    }

    #[test]
    fn a_hole_is_filled_before_the_tail() {
        let mut pool = PagePool::new(16);
        let a = pool.alloc(4).unwrap();
        let _b = pool.alloc(4).unwrap();
        pool.free(a, 4).unwrap();
        assert_eq!(pool.alloc(3), Some(0));
        assert_eq!(pool.alloc(2), Some(8));
        assert_eq!(pool.alloc(1), Some(3));
    }

    #[test]
    fn neighbouring_frees_merge_into_one_run() {
        let mut pool = PagePool::new(12);
        let a = pool.alloc(4).unwrap();
        let b = pool.alloc(4).unwrap();
        let c = pool.alloc(4).unwrap();
        pool.free(a, 4).unwrap();
        pool.free(c, 4).unwrap();
        assert_eq!(pool.largest_free_run(), 4);
        assert_eq!(pool.alloc(8), None);
        pool.free(b, 4).unwrap();
        assert_eq!(pool.largest_free_run(), 12);
        assert_eq!(pool.alloc(12), Some(0));
    }

    #[test]
    fn fragmentation_refuses_what_does_not_fit_contiguously() {
        let mut pool = PagePool::new(12);
        let a = pool.alloc(4).unwrap();
        let _b = pool.alloc(4).unwrap();
        let c = pool.alloc(4).unwrap();
        pool.free(a, 4).unwrap();
        pool.free(c, 4).unwrap();
        // 8 pages free, but in two runs of 4.
        assert_eq!(pool.total() - pool.in_use(), 8);
        assert_eq!(pool.alloc(5), None);
        assert_eq!(pool.alloc(4), Some(0));
    }

    #[test]
    fn free_refuses_anything_but_a_whole_allocation() {
        let mut pool = PagePool::new(8);
        let a = pool.alloc(4).unwrap();
        assert_eq!(pool.free(a + 1, 3), Err(FreeError::NotAllocated));
        assert_eq!(pool.free(a, 2), Err(FreeError::SizeMismatch { allocated: 4 }));
        assert_eq!(pool.free(6, 1), Err(FreeError::NotAllocated));
        assert_eq!(pool.in_use(), 4);
        pool.free(a, 4).unwrap();
        assert_eq!(pool.free(a, 4), Err(FreeError::NotAllocated));
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn is_allocated_covers_exactly_the_live_ranges() {
        let mut pool = PagePool::new(16);
        let a = pool.alloc(4).unwrap();
        let b = pool.alloc(4).unwrap();
        assert!(pool.is_allocated(a, 4));
        assert!(pool.is_allocated(a + 1, 2));
        assert!(pool.is_allocated(b + 3, 1));
        // Spanning two allocations is not one allocation.
        assert!(!pool.is_allocated(a + 3, 2));
        assert!(!pool.is_allocated(8, 1));
        pool.free(a, 4).unwrap();
        assert!(!pool.is_allocated(a, 1));
    }

    #[test]
    fn peak_tracks_the_high_water_mark() {
        let mut pool = PagePool::new(16);
        let a = pool.alloc(6).unwrap();
        let b = pool.alloc(6).unwrap();
        pool.free(a, 6).unwrap();
        pool.free(b, 6).unwrap();
        assert_eq!(pool.in_use(), 0);
        assert_eq!(pool.peak(), 12);
        assert_eq!(pool.allocation_count(), 0);
    }

    /// Loading and unloading the same app over and over, the failure that
    /// used to exhaust the pool, never runs out.
    #[test]
    fn repeated_load_and_unload_never_exhausts() {
        let mut pool = PagePool::new(4096);
        // A code image of 585728 bytes is 143 pages.
        for _ in 0..10_000 {
            let first = pool.alloc(143).expect("pool exhausted by reuse");
            pool.free(first, 143).unwrap();
        }
        assert_eq!(pool.in_use(), 0);
        assert_eq!(pool.peak(), 143);
    }

    /// Several apps loaded and evicted in an interleaved order: every freed
    /// range is reclaimed and the pool ends empty.
    #[test]
    fn interleaved_loads_and_evictions_reclaim_everything() {
        let mut pool = PagePool::new(4096);
        let sizes = [143usize, 17, 512, 1, 300, 64, 999, 2];
        let mut live: Vec<(usize, usize)> = Vec::new();
        for round in 0..2_000usize {
            let pages = sizes[round % sizes.len()];
            match pool.alloc(pages) {
                Some(first) => live.push((first, pages)),
                None => {
                    // Evict the oldest and carry on, like the app LRU does.
                    let (first, pages) = live.remove(0);
                    pool.free(first, pages).unwrap();
                }
            }
            if round % 3 == 0 && live.len() > 4 {
                let (first, pages) = live.remove(live.len() / 2);
                pool.free(first, pages).unwrap();
            }
            // Live allocations never overlap.
            let mut sorted = live.clone();
            sorted.sort();
            for w in sorted.windows(2) {
                assert!(w[0].0 + w[0].1 <= w[1].0, "overlap: {:?}", w);
            }
            assert_eq!(pool.in_use(), live.iter().map(|&(_, p)| p).sum::<usize>());
        }
        for (first, pages) in live.drain(..) {
            pool.free(first, pages).unwrap();
        }
        assert_eq!(pool.in_use(), 0);
        assert_eq!(pool.largest_free_run(), 4096);
    }
}
