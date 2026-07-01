// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT
//
// Extracted from ackinacki/block-manager block_applier.rs
// Original: 2022-2025 (c) Contributors to the GOSH DAO.

use std::collections::HashSet;
use std::collections::VecDeque;

const DEFAULT_CAPACITY: usize = 10_000;

/// Bounded hash-set filter for block deduplication.
/// When receiving from multiple BK connections, the same block
/// can arrive more than once — this filter drops duplicates.
pub struct RecentBlockFilter {
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl RecentBlockFilter {
    pub fn new(capacity: usize) -> Self {
        Self {
            set: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Returns `true` if the hash is new (should be processed), `false` if duplicate.
    pub fn check_and_insert(&mut self, hash: [u8; 32]) -> bool {
        if self.set.contains(&hash) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(hash);
        self.order.push_back(hash);
        true
    }
}

impl Default for RecentBlockFilter {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_filters_duplicates() {
        let mut f = RecentBlockFilter::new(3);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];

        assert!(f.check_and_insert(h1));
        assert!(f.check_and_insert(h2));
        assert!(!f.check_and_insert(h1)); // duplicate
    }

    #[test]
    fn dedup_evicts_oldest() {
        let mut f = RecentBlockFilter::new(2);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];

        assert!(f.check_and_insert(h1));
        assert!(f.check_and_insert(h2));
        assert!(f.check_and_insert(h3)); // evicts h1
        assert!(f.check_and_insert(h1)); // h1 is new again
        assert!(!f.check_and_insert(h3)); // h3 still there
    }

    #[test]
    fn default_creates_with_10000_capacity() {
        let f = RecentBlockFilter::default();
        assert_eq!(f.capacity, DEFAULT_CAPACITY);
        assert_eq!(f.capacity, 10_000);
    }

    #[test]
    fn insert_many_up_to_capacity() {
        let cap = 100;
        let mut f = RecentBlockFilter::new(cap);
        for i in 0..cap {
            let mut hash = [0u8; 32];
            hash[0] = (i & 0xFF) as u8;
            hash[1] = ((i >> 8) & 0xFF) as u8;
            assert!(f.check_and_insert(hash));
        }
        assert_eq!(f.set.len(), cap);
        assert_eq!(f.order.len(), cap);
    }

    #[test]
    fn check_and_insert_returns_false_immediately_after_insert() {
        let mut f = RecentBlockFilter::new(10);
        let h = [0xABu8; 32];
        assert!(f.check_and_insert(h));
        assert!(!f.check_and_insert(h));
        assert!(!f.check_and_insert(h));
    }

    #[test]
    fn after_eviction_old_items_reinsertable() {
        let mut f = RecentBlockFilter::new(3);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        let h4 = [4u8; 32];
        let h5 = [5u8; 32];

        assert!(f.check_and_insert(h1));
        assert!(f.check_and_insert(h2));
        assert!(f.check_and_insert(h3));
        // Capacity is 3. Next insert evicts h1.
        assert!(f.check_and_insert(h4)); // evicts h1
        assert!(f.check_and_insert(h5)); // evicts h2
                                         // h1 and h2 are evicted, so they can be re-inserted
        assert!(f.check_and_insert(h1));
        assert!(f.check_and_insert(h2));
        // h3 got evicted by h1, h4 got evicted by h2
        assert!(f.check_and_insert(h3));
        assert!(f.check_and_insert(h4));
    }

    #[test]
    fn capacity_one() {
        let mut f = RecentBlockFilter::new(1);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];

        assert!(f.check_and_insert(h1));
        assert!(!f.check_and_insert(h1)); // dup
        assert!(f.check_and_insert(h2)); // evicts h1
        assert!(f.check_and_insert(h1)); // h1 can be re-inserted
        assert!(!f.check_and_insert(h1)); // dup again
    }

    #[test]
    fn set_and_order_stay_in_sync() {
        let mut f = RecentBlockFilter::new(3);
        for i in 0u8..10 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            f.check_and_insert(hash);
        }
        assert_eq!(f.set.len(), 3);
        assert_eq!(f.order.len(), 3);
    }
}
