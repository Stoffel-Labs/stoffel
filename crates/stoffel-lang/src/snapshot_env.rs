//! Related abstract environments share stable binding ids and immutable pages.
//! Interning a name never creates a binding in another branch: presence and
//! values live in each snapshot, independently of the shared name index.
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

const PAGE_SIZE: usize = 64;

/// Repeated AST visits reuse a binding id without rehashing its name. Slots
/// never disappear; binding presence still belongs to each environment page.
#[derive(Debug, Default)]
struct SlotIndex<'a> {
    names: RefCell<HashMap<&'a str, usize>>,
    cache: [Cell<Option<(&'a str, usize)>>; 32],
}

impl<'a> SlotIndex<'a> {
    fn get(&self, name: &str) -> Option<usize> {
        // Equal names at different AST sites share the same cache entry.
        // This only selects a slot; full equality still validates every hit.
        let bytes = name.as_bytes();
        let first = bytes.first().copied().unwrap_or(0) as usize;
        let last = bytes.last().copied().unwrap_or(0) as usize;
        let cache = &self.cache[(first ^ (last << 2) ^ bytes.len()) & 31];
        if let Some((key, id)) = cache.get() {
            if key == name {
                return Some(id);
            }
        }
        let names = self.names.borrow();
        let (&key, &id) = names.get_key_value(name)?;
        cache.set(Some((key, id)));
        Some(id)
    }

    fn intern(&self, name: &'a str) -> usize {
        if let Some(id) = self.get(name) {
            return id;
        }
        let mut names = self.names.borrow_mut();
        let id = names.len();
        names.insert(name, id);
        id
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SnapshotEnv<'a, V> {
    slots: Rc<SlotIndex<'a>>,
    pages: Vec<Rc<Vec<Option<V>>>>,
}

impl<V> Default for SnapshotEnv<'_, V> {
    fn default() -> Self {
        Self {
            slots: Rc::new(SlotIndex::default()),
            pages: Vec::new(),
        }
    }
}

impl<'a, V: Clone + PartialEq> SnapshotEnv<'a, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&V> {
        let id = self.slots.get(name)?;
        self.get_slot(id)
    }

    /// AST names outlive the environment, so cache their exact string slice.
    /// Short-lived lookup strings continue through `get` and full equality.
    pub fn get_ast(&self, name: &'a str) -> Option<&V> {
        let cache = &self.slots.cache[((name.as_ptr() as usize) >> 4) & 31];
        let id = match cache.get() {
            Some((key, id)) if std::ptr::eq(key, name) => id,
            _ => {
                let id = self.slots.get(name)?;
                cache.set(Some((name, id)));
                id
            }
        };
        self.get_slot(id)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut V> {
        let id = self.slots.get(name)?;
        self.get_slot_mut(id)
    }

    pub fn insert(&mut self, name: &'a str, value: V) {
        let id = self.slots.intern(name);
        self.set_slot(id, Some(value));
    }

    pub fn remove(&mut self, name: &str) {
        let id = self.slots.get(name);
        if let Some(id) = id {
            if self.get_slot(id).is_some() {
                self.set_slot(id, None);
            }
        }
    }

    pub fn get_slot(&self, id: usize) -> Option<&V> {
        self.pages
            .get(id / PAGE_SIZE)?
            .get(id % PAGE_SIZE)?
            .as_ref()
    }

    pub fn get_slot_mut(&mut self, id: usize) -> Option<&mut V> {
        self.get_slot(id)?;
        Rc::make_mut(&mut self.pages[id / PAGE_SIZE])[id % PAGE_SIZE].as_mut()
    }

    pub fn set_slot(&mut self, id: usize, value: Option<V>) {
        // Reassigning an unchanged abstract fact must not detach a shared page.
        if self.get_slot(id) == value.as_ref() {
            return;
        }
        while self.pages.len() <= id / PAGE_SIZE {
            self.pages.push(Rc::new(vec![None; PAGE_SIZE]));
        }
        Rc::make_mut(&mut self.pages[id / PAGE_SIZE])[id % PAGE_SIZE] = value;
    }

    /// Branches may allocate different names after the snapshot. The shared
    /// interner ensures those names still have distinct ids, including holes.
    pub fn changed_slots(&self, other: &Self) -> Vec<usize> {
        assert!(
            Rc::ptr_eq(&self.slots, &other.slots),
            "unrelated environment snapshots"
        );
        let mut changed = Vec::new();
        for page in 0..self.pages.len().max(other.pages.len()) {
            if matches!((self.pages.get(page), other.pages.get(page)),
                (Some(a), Some(b)) if Rc::ptr_eq(a, b))
            {
                continue;
            }
            for offset in 0..PAGE_SIZE {
                let id = page * PAGE_SIZE + offset;
                if self.get_slot(id) != other.get_slot(id) {
                    changed.push(id);
                }
            }
        }
        changed
    }
}

impl<V: Clone + PartialEq> PartialEq for SnapshotEnv<'_, V> {
    fn eq(&self, other: &Self) -> bool {
        if Rc::ptr_eq(&self.slots, &other.slots) {
            // Do not allocate the changed-slot list just to test convergence.
            (0..self.pages.len().max(other.pages.len())).all(|page| {
                matches!((self.pages.get(page), other.pages.get(page)),
                    (Some(a), Some(b)) if Rc::ptr_eq(a, b))
                    || (0..PAGE_SIZE).all(|offset| {
                        let id = page * PAGE_SIZE + offset;
                        self.get_slot(id) == other.get_slot(id)
                    })
            })
        } else {
            let slots = self.slots.names.borrow();
            let other_slots = other.slots.names.borrow();
            slots
                .iter()
                .all(|(name, &id)| self.get_slot(id) == other.get(name))
                && other_slots
                    .iter()
                    .all(|(name, &id)| other.get_slot(id) == self.get(name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SnapshotEnv;

    #[test]
    fn cached_slots_survive_collisions_shadowing_and_absent_branch_bindings() {
        let names: Vec<_> = (0..256).map(|i| format!("name_{i}")).collect();
        let copies = names.clone();
        let mut env = super::SnapshotEnv::new();
        for (i, name) in names.iter().enumerate() {
            env.insert(name, i);
        }
        let mut branch = env.clone();
        for name in &names {
            branch.remove(name);
        }
        for _ in 0..3 {
            for (i, name) in copies.iter().enumerate() {
                assert_eq!(env.get(name), Some(&i));
                assert_eq!(env.get_ast(name), Some(&i));
                assert_eq!(branch.get_ast(name), None);
                assert_eq!(branch.get(name), None);
            }
        }
        branch.insert(&names[0], 999);
        assert_eq!(branch.get(&copies[0]), Some(&999));
        assert_eq!(env.get(&copies[0]), Some(&0));
        assert_ne!(env, branch);
    }

    #[test]
    fn snapshots_keep_branch_bindings_isolated_and_restore_removed_values() {
        let names: Vec<_> = (0..140).map(|i| format!("binding_{i}")).collect();
        let mut base = SnapshotEnv::new();
        for (i, name) in names.iter().take(100).enumerate() {
            base.insert(name, i);
        }
        let mut left = base.clone();
        let mut right = base.clone();
        left.insert(&names[120], 120);
        right.insert(&names[121], 121);
        left.insert(&names[63], 900);
        right.remove(&names[64]);
        assert_eq!(base.get(&names[63]), Some(&63));
        assert_eq!(left.get(&names[121]), None);
        assert_eq!(right.get(&names[120]), None);
        assert_eq!(base.changed_slots(&left).len(), 2);
        assert_eq!(base.changed_slots(&right).len(), 2);
        assert_eq!(left.changed_slots(&right).len(), 4);
        right.insert(&names[64], 64);
        right.remove(&names[121]);
        assert_eq!(right, base, "absent trailing slots do not change equality");
        for id in base.changed_slots(&left) {
            left.set_slot(id, base.get_slot(id).copied());
        }
        assert_eq!(left, base);
    }
}
