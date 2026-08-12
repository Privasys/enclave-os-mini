// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! In-enclave LRU over node records.
//!
//! Node records are immutable (a `NodeKey` is written by exactly one
//! commit and never again), so the cache needs no invalidation logic to
//! stay coherent — only pruning clears it wholesale, to keep deleted
//! history from lingering. Cached nodes are still hash-verified against
//! the parent's expectation on every use: the cache removes host I/O,
//! never trust checks.
//!
//! Eviction is least-recently-used via a monotonic access tick with an
//! O(capacity) scan on eviction — capacities are ~10³ and evictions are
//! per cache-miss, so the scan is noise next to a host round trip.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::node::{Node, NodeKey};

pub(crate) struct NodeCache {
    inner: Mutex<Inner>,
}

struct Inner {
    capacity: usize,
    tick: u64,
    map: HashMap<NodeKey, (Node, u64)>,
}

impl NodeCache {
    /// `capacity` 0 disables caching entirely.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner { capacity, tick: 0, map: HashMap::new() }),
        }
    }

    pub fn get(&self, key: &NodeKey) -> Option<Node> {
        let mut inner = self.inner.lock().unwrap();
        inner.tick += 1;
        let tick = inner.tick;
        match inner.map.get_mut(key) {
            Some((node, last_used)) => {
                *last_used = tick;
                Some(node.clone())
            }
            None => None,
        }
    }

    pub fn put(&self, key: NodeKey, node: Node) {
        let mut inner = self.inner.lock().unwrap();
        if inner.capacity == 0 {
            return;
        }
        if inner.map.len() >= inner.capacity && !inner.map.contains_key(&key) {
            if let Some(oldest) = inner
                .map
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| k.clone())
            {
                inner.map.remove(&oldest);
            }
        }
        inner.tick += 1;
        let tick = inner.tick;
        inner.map.insert(key, (node, tick));
    }

    /// Drop everything (pruning; capacity changes).
    pub fn clear(&self) {
        self.inner.lock().unwrap().map.clear();
    }

    pub fn set_capacity(&self, capacity: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.capacity = capacity;
        inner.map.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{LeafNode, Node};

    fn leaf(seed: u8) -> Node {
        Node::Leaf(LeafNode { path: [seed; 32], vh: [seed; 32], value_version: 1 })
    }

    fn nk(version: u64) -> NodeKey {
        NodeKey { version, prefix: vec![] }
    }

    #[test]
    fn evicts_least_recently_used() {
        let cache = NodeCache::new(2);
        cache.put(nk(1), leaf(1));
        cache.put(nk(2), leaf(2));
        assert!(cache.get(&nk(1)).is_some()); // 1 now more recent than 2
        cache.put(nk(3), leaf(3)); // evicts 2
        assert!(cache.get(&nk(1)).is_some());
        assert!(cache.get(&nk(2)).is_none());
        assert!(cache.get(&nk(3)).is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn zero_capacity_disables() {
        let cache = NodeCache::new(0);
        cache.put(nk(1), leaf(1));
        assert!(cache.get(&nk(1)).is_none());
        assert_eq!(cache.len(), 0);
    }
}
