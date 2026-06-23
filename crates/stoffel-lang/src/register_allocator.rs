use std::collections::{HashMap, HashSet};
use stoffel_vm_types::instructions::Instruction;

// --- Types ---

/// Represents a virtual register used during initial code generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VirtualRegister(pub usize);

/// Represents a physical hardware register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PhysicalRegister(pub usize);

/// Represents the live interval of a virtual register [start, end).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveInterval {
    pub start: usize, // Instruction index where the register is defined
    pub end: usize,   // Instruction index after the last use
}

/// Represents the interference graph. Nodes are virtual registers.
/// Edges connect registers that are live at the same time.
#[derive(Debug, Clone, Default)]
pub struct InterferenceGraph {
    adj: HashMap<VirtualRegister, HashSet<VirtualRegister>>,
    nodes: HashSet<VirtualRegister>, // Keep track of all nodes (virtual registers)
}

/// Represents the result of register allocation.
pub type Allocation = HashMap<VirtualRegister, PhysicalRegister>;

/// Error type for allocation failures (e.g., needs spilling).
#[derive(Debug, Clone)]
pub enum AllocationError {
    PoolExhausted(VirtualRegister, bool), // Registers that could not be colored due to pool exhaustion
    NeedsSpilling(Vec<VirtualRegister>),  // Registers that could not be colored
}

// --- Liveness Analysis ---

/// Computes the live intervals for all virtual registers in a sequence of instructions.
/// Legacy linear analysis wrapper (no CFG). Prefer `analyze_liveness_cfg_with_liveins`.
pub fn analyze_liveness(instructions: &[Instruction]) -> HashMap<VirtualRegister, LiveInterval> {
    analyze_liveness_with_liveins(instructions, &[])
}

/// Computes the live intervals for all virtual registers with an explicit set of live-in parameters.
/// Legacy linear analysis wrapper (no CFG). Prefer `analyze_liveness_cfg_with_liveins`.
pub fn analyze_liveness_with_liveins(
    instructions: &[Instruction],
    live_in: &[VirtualRegister],
) -> HashMap<VirtualRegister, LiveInterval> {
    use crate::register_allocator::InstructionRegisterAnalysis;
    let mut intervals: HashMap<VirtualRegister, LiveInterval> = HashMap::new();
    let mut last_use: HashMap<VirtualRegister, usize> = HashMap::new();
    let mut defined: HashMap<VirtualRegister, usize> = HashMap::new();

    // Seed live-in parameters as live from function entry (index 0)
    for &vr in live_in {
        intervals
            .entry(vr)
            .or_insert(LiveInterval { start: 0, end: 0 });
    }

    // Helper to update interval start point
    let update_start = |intervals: &mut HashMap<VirtualRegister, LiveInterval>,
                        vr: VirtualRegister,
                        start_point: usize| {
        intervals
            .entry(vr)
            .or_insert(LiveInterval { start: 0, end: 0 })
            .start = start_point;
    };

    // First pass: Find definitions and last uses
    for (i, instruction) in instructions.iter().enumerate() {
        let instruction_index = i; // Index of the current instruction

        // Process uses first (update last_use)
        for vr in instruction.uses() {
            last_use.insert(vr, instruction_index);
            // Ensure the register exists in intervals, even if defined later (e.g., function args)
            intervals
                .entry(vr)
                .or_insert(LiveInterval { start: 0, end: 0 });
        }

        // Process definitions (update defined, initialize interval)
        for vr in instruction.defs() {
            if let std::collections::hash_map::Entry::Vacant(e) = defined.entry(vr) {
                e.insert(instruction_index);
                update_start(&mut intervals, vr, instruction_index);
            }
            // Definition also counts as a use for liveness purposes
            last_use.insert(vr, instruction_index);
        }
    }

    // Second pass: Set the end point for each interval
    for (vr, interval) in intervals.iter_mut() {
        // The interval ends *after* the last use instruction.
        interval.end = last_use
            .get(vr)
            .map_or(interval.start, |last_use_idx| last_use_idx + 1);
        // Ensure start is correctly set from the 'defined' map
        if let Some(def_idx) = defined.get(vr) {
            interval.start = *def_idx;
        } else {
            // If not defined in this block (e.g., function parameter), start at 0
            interval.start = 0;
        }
        // Ensure end is at least start + 1 if defined and used in the same instruction
        if interval.end <= interval.start {
            interval.end = interval.start + 1;
        }
    }

    intervals
}

/// CFG-based liveness with explicit labels (block successors) and live-ins.
/// Builds basic blocks, runs iterative dataflow to compute live-in/out, then per-instruction liveness,
/// and finally collapses to single intervals per virtual register.
pub fn analyze_liveness_cfg_with_liveins(
    instructions: &[Instruction],
    labels: &HashMap<String, usize>,
    live_in: &[VirtualRegister],
) -> HashMap<VirtualRegister, LiveInterval> {
    use crate::register_allocator::InstructionRegisterAnalysis;
    let n = instructions.len();
    // Early exit
    if n == 0 {
        return HashMap::new();
    }

    // Collect all VRs seen. Each VR gets a dense index so liveness can run over
    // fixed-size bitsets (Vec<u64>) instead of cloning HashSets — the per-instruction
    // HashSet clones were the O(n * live_set) blowup that made large functions
    // (e.g. the vectorized AES circuit) take minutes to compile.
    let mut all_vrs: HashSet<VirtualRegister> = HashSet::new();
    for inst in instructions.iter() {
        for u in inst.uses() {
            all_vrs.insert(u);
        }
        for d in inst.defs() {
            all_vrs.insert(d);
        }
    }
    for &vr in live_in {
        all_vrs.insert(vr);
    }

    // Dense, deterministic indexing (sorted so register allocation is reproducible).
    let mut vrs: Vec<VirtualRegister> = all_vrs.into_iter().collect();
    vrs.sort_unstable();
    let num_vrs = vrs.len();
    let mut vr_index: HashMap<VirtualRegister, u32> = HashMap::with_capacity(num_vrs);
    for (i, &vr) in vrs.iter().enumerate() {
        vr_index.insert(vr, i as u32);
    }

    // Precompute per-instruction use/def index lists once, so the hot loops below
    // never re-call uses()/defs() (each allocates a Vec) or hash a VirtualRegister.
    let mut inst_uses: Vec<Vec<u32>> = Vec::with_capacity(n);
    let mut inst_defs: Vec<Vec<u32>> = Vec::with_capacity(n);
    for inst in instructions.iter() {
        inst_uses.push(inst.uses().iter().map(|u| vr_index[u]).collect());
        inst_defs.push(inst.defs().iter().map(|d| vr_index[d]).collect());
    }

    // Bitset over `words` u64 lanes, one bit per dense VR index.
    let words = num_vrs.div_ceil(64);
    #[inline]
    fn bit_set(bits: &mut [u64], i: u32) {
        bits[(i >> 6) as usize] |= 1u64 << (i & 63);
    }

    // 1) Determine basic block boundaries
    let mut block_starts: HashSet<usize> = HashSet::new();
    block_starts.insert(0);
    for &idx in labels.values() {
        if idx < n {
            block_starts.insert(idx);
        }
    }
    for (i, instruction) in instructions.iter().enumerate() {
        match instruction {
            Instruction::JMP(_)
            | Instruction::JMPEQ(_)
            | Instruction::JMPNEQ(_)
            | Instruction::JMPLT(_)
            | Instruction::JMPGT(_)
            | Instruction::RET(_)
                if i + 1 < n =>
            {
                block_starts.insert(i + 1);
            }
            _ => {}
        }
    }
    // Create sorted list of starts
    let mut starts: Vec<usize> = block_starts.into_iter().collect();
    starts.sort_unstable();
    // Map: inst index -> block id
    let mut inst2block: Vec<usize> = vec![0; n];
    for (bi, &s) in starts.iter().enumerate() {
        let end = starts.get(bi + 1).copied().unwrap_or(n);
        for block_id in inst2block.iter_mut().take(end).skip(s) {
            *block_id = bi;
        }
    }

    struct BlockInfo {
        start: usize,
        end: usize, // exclusive
        succs: Vec<usize>,
        use_bits: Vec<u64>, // used before any in-block def
        def_bits: Vec<u64>, // defined anywhere in the block
    }

    let mut blocks: Vec<BlockInfo> = Vec::with_capacity(starts.len());
    for (bi, &s) in starts.iter().enumerate() {
        let e = starts.get(bi + 1).copied().unwrap_or(n);
        blocks.push(BlockInfo {
            start: s,
            end: e,
            succs: Vec::new(),
            use_bits: vec![0u64; words],
            def_bits: vec![0u64; words],
        });
    }

    // 2) Compute successors per block
    // Helper: get block id by instruction index
    let label_to_block = |lbl: &String| -> Option<usize> {
        labels
            .get(lbl)
            .and_then(|&idx| if idx < n { Some(inst2block[idx]) } else { None })
    };
    for (bi, block) in blocks.iter_mut().enumerate() {
        if block.start == block.end {
            continue;
        }
        let last_i = block.end - 1;
        match &instructions[last_i] {
            Instruction::JMP(lbl) => {
                if let Some(t) = label_to_block(lbl) {
                    block.succs.push(t);
                }
            }
            Instruction::JMPEQ(lbl)
            | Instruction::JMPNEQ(lbl)
            | Instruction::JMPLT(lbl)
            | Instruction::JMPGT(lbl) => {
                if let Some(t) = label_to_block(lbl) {
                    block.succs.push(t);
                }
                // fallthrough
                if let Some(next_start) = starts.get(bi + 1).copied() {
                    if next_start < n {
                        block.succs.push(bi + 1);
                    }
                }
            }
            Instruction::RET(_) => { /* no successors */ }
            _ => {
                // fallthrough
                if let Some(_next) = starts.get(bi + 1) {
                    block.succs.push(bi + 1);
                }
            }
        }
        // Dedup succs
        let mut uniq = HashSet::new();
        block.succs.retain(|s| uniq.insert(*s));
    }

    // 3) Compute use/def per block (use = used before being defined within the block).
    for b in &mut blocks {
        for i in b.start..b.end {
            for &u in &inst_uses[i] {
                if (b.def_bits[(u >> 6) as usize] >> (u & 63)) & 1 == 0 {
                    bit_set(&mut b.use_bits, u);
                }
            }
            for &d in &inst_defs[i] {
                bit_set(&mut b.def_bits, d);
            }
        }
    }

    // 4) Iterative dataflow for live_in/live_out over bitsets (no per-block clones).
    let mut live_in_b: Vec<Vec<u64>> = vec![vec![0u64; words]; blocks.len()];
    let mut live_out_b: Vec<Vec<u64>> = vec![vec![0u64; words]; blocks.len()];

    // Seed entry live-ins.
    let entry_block = inst2block[0];
    let mut entry_seed = vec![0u64; words];
    for &vr in live_in {
        bit_set(&mut entry_seed, vr_index[&vr]);
    }
    live_in_b[entry_block].copy_from_slice(&entry_seed);

    let mut new_out = vec![0u64; words];
    let mut changed = true;
    while changed {
        changed = false;
        for bi in (0..blocks.len()).rev() {
            // out[B] = union of in[S] over successors
            new_out.fill(0);
            for &s in &blocks[bi].succs {
                let src = &live_in_b[s];
                for (dst, src) in new_out.iter_mut().zip(src.iter()).take(words) {
                    *dst |= *src;
                }
            }
            {
                let dst = &mut live_out_b[bi];
                for (dst_word, new_word) in dst.iter_mut().zip(new_out.iter()).take(words) {
                    if *dst_word != *new_word {
                        *dst_word = *new_word;
                        changed = true;
                    }
                }
            }
            // in[B] = use[B] ∪ (out[B] \ def[B]) (∪ seed at entry)
            let block = &blocks[bi];
            let out = &live_out_b[bi];
            let dst = &mut live_in_b[bi];
            for w in 0..words {
                let mut v = block.use_bits[w] | (out[w] & !block.def_bits[w]);
                if bi == entry_block {
                    v |= entry_seed[w];
                }
                if dst[w] != v {
                    dst[w] = v;
                    changed = true;
                }
            }
        }
    }

    // 5) + 6) Extract one interval per VR from a single SPARSE backward walk.
    //   def_first[v] = first instruction index defining v
    //   end_idx[v]   = (highest index where v is live-out) + 1, else 0
    //
    // The live set is maintained sparsely (a presence vector mutated by the
    // per-instruction uses/defs), so the walk costs O(instructions + uses/defs)
    // instead of the O(instructions * num_vrs/64) of a dense per-instruction
    // bitset scan. That dense term is quadratic in function size (num_vrs grows
    // with the instruction count) and dominated allocation time for very large
    // fully-unrolled/inlined functions; the sparse walk removes it.
    let mut def_first = vec![usize::MAX; num_vrs];
    for (i, defs) in inst_defs.iter().enumerate() {
        for &d in defs {
            let di = d as usize;
            if i < def_first[di] {
                def_first[di] = i;
            }
        }
    }

    let mut end_idx = vec![0usize; num_vrs];
    // Sparse live set: `present[vi]` is membership; `touched` records indices set
    // during the current block so they can be reset in O(touched) before the next.
    let mut present = vec![false; num_vrs];
    let mut touched: Vec<usize> = Vec::new();
    for (bi, block) in blocks.iter().enumerate() {
        for &vi in &touched {
            present[vi] = false;
        }
        touched.clear();
        // Seed with the block's live-out. Its last instruction is at index
        // block.end-1, so the highest live-out index for these VRs is block.end-1
        // (→ end_idx = block.end), matching the dense walk's `i + 1` at that index.
        for (w, word) in live_out_b[bi].iter().enumerate().take(words) {
            let mut x = *word;
            while x != 0 {
                let vi = w * 64 + x.trailing_zeros() as usize;
                x &= x - 1;
                if !present[vi] {
                    present[vi] = true;
                    touched.push(vi);
                    if block.end > end_idx[vi] {
                        end_idx[vi] = block.end;
                    }
                }
            }
        }
        for i in (block.start..block.end).rev() {
            // `present` is live_out_inst[i]. Step to live_in_inst[i] = (live − defs) ∪ uses.
            for &d in &inst_defs[i] {
                present[d as usize] = false;
            }
            for &u in &inst_uses[i] {
                let ui = u as usize;
                if !present[ui] {
                    present[ui] = true;
                    touched.push(ui);
                    // Newly live going backward: u becomes live-out at i-1, so its
                    // highest live-out index is i-1 (→ end_idx = i), exactly what the
                    // dense walk recorded when it first saw u live-out at i-1.
                    if i > end_idx[ui] {
                        end_idx[ui] = i;
                    }
                }
            }
        }
    }

    let mut intervals: HashMap<VirtualRegister, LiveInterval> = HashMap::with_capacity(num_vrs);
    for (vi, &vr) in vrs.iter().enumerate() {
        // A VR with no def is a function live-in (parameter): live from entry, so
        // start at 0 — a conservative interval that is never too short.
        let start = if def_first[vi] != usize::MAX {
            def_first[vi]
        } else {
            0
        };
        let mut end = end_idx[vi];
        if def_first[vi] != usize::MAX {
            let d = def_first[vi];
            if end < d + 1 {
                end = d + 1;
            }
        }
        if end <= start {
            end = start + 1;
        }
        intervals.insert(vr, LiveInterval { start, end });
    }

    intervals
}

// --- Interference Graph ---

impl InterferenceGraph {
    /// Adds a node (virtual register) to the graph.
    pub fn add_node(&mut self, vr: VirtualRegister) {
        self.nodes.insert(vr);
        self.adj.entry(vr).or_default(); // Ensure entry exists even if no edges yet
    }

    /// Adds an edge between two virtual registers.
    pub fn add_edge(&mut self, vr1: VirtualRegister, vr2: VirtualRegister) {
        if vr1 != vr2 {
            self.add_node(vr1); // Ensure nodes exist
            self.add_node(vr2);
            self.adj.entry(vr1).or_default().insert(vr2);
            self.adj.entry(vr2).or_default().insert(vr1);
        }
    }

    /// Returns the neighbors of a given virtual register.
    pub fn neighbors(&self, vr: &VirtualRegister) -> Option<&HashSet<VirtualRegister>> {
        self.adj.get(vr)
    }

    /// Returns the degree of a node (number of neighbors).
    pub fn degree(&self, vr: &VirtualRegister) -> usize {
        self.neighbors(vr).map_or(0, |neighbors| neighbors.len())
    }

    /// Removes a node and its associated edges from the graph.
    pub fn remove_node(&mut self, vr_to_remove: &VirtualRegister) {
        if let Some(neighbors) = self.adj.remove(vr_to_remove) {
            for neighbor in neighbors {
                if let Some(neighbor_adj) = self.adj.get_mut(&neighbor) {
                    neighbor_adj.remove(vr_to_remove);
                }
            }
        }
        self.nodes.remove(vr_to_remove);
    }
}

/// Builds the interference graph from live intervals.
pub fn build_interference_graph(
    intervals: &HashMap<VirtualRegister, LiveInterval>,
) -> InterferenceGraph {
    let mut graph = InterferenceGraph::default();

    // Sweep line over intervals sorted by start point. Two intervals interfere iff they
    // overlap; instead of checking all O(V^2) pairs, we keep an "active" set of intervals
    // still live at the current start and connect each new interval only to those. This
    // builds the exact same overlap graph in O(V log V + E) where E is the real edge count.
    let mut items: Vec<(VirtualRegister, usize, usize)> = intervals
        .iter()
        .map(|(&vr, iv)| (vr, iv.start, iv.end))
        .collect();
    for &(vr, _, _) in &items {
        graph.add_node(vr);
    }
    // Sort by start, then by VR for deterministic edge-insertion order.
    items.sort_unstable_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

    // active holds (end, vr) for intervals that started earlier and have not yet expired.
    let mut active: Vec<(usize, VirtualRegister)> = Vec::new();
    for &(vr, start, end) in &items {
        // Expire intervals that ended at or before this start (half-open [start, end)).
        active.retain(|&(a_end, _)| a_end > start);
        for &(_, other) in &active {
            graph.add_edge(vr, other);
        }
        active.push((end, vr));
    }

    graph
}

// --- Graph Coloring (Greedy Algorithm) ---

/// Assigns physical registers (colors) to virtual registers using a greedy graph coloring algorithm.
/// `k_clear` is the number of available clear physical registers.
/// `k_secret` is the number of available secret physical registers.
/// `secrecy_map` indicates whether each virtual register requires a secret register.
pub fn color_graph(
    graph: &InterferenceGraph,
    k_clear: usize,
    k_secret: usize,
    secrecy_map: &HashMap<VirtualRegister, bool>,
    precolored: &HashMap<VirtualRegister, PhysicalRegister>,
) -> Result<Allocation, AllocationError> {
    // --- Helpers to respect register pools ---
    fn pool_degree(
        g: &InterferenceGraph,
        v: &VirtualRegister,
        secrecy: &HashMap<VirtualRegister, bool>,
    ) -> usize {
        let my_secret = *secrecy
            .get(v)
            .expect("missing secrecy_map entry for virtual register");
        g.neighbors(v)
            .map(|ns| {
                ns.iter()
                    .filter(|n| {
                        *secrecy
                            .get(*n)
                            .expect("missing secrecy_map entry for virtual register")
                            == my_secret
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn pool_capacity(
        v: &VirtualRegister,
        k_clear: usize,
        k_secret: usize,
        secrecy: &HashMap<VirtualRegister, bool>,
    ) -> usize {
        if *secrecy
            .get(v)
            .expect("missing secrecy_map entry for virtual register")
        {
            k_secret
        } else {
            k_clear
        }
    }

    let mut sg = graph.clone();
    // Validate precolored mapping: forbid using reserved R0
    for (_vr, _pr) in precolored.iter() {
        // Allow precoloring to R0: parameters may live in the ABI return/arg register.
    }

    // Start with precolored allocation (e.g., ABI-fixed registers like parameters)
    let mut allocation: Allocation = precolored.clone();
    // Remove precolored nodes from the simplification graph so they are not recolored/spilled
    for v in allocation.keys() {
        if sg.nodes.contains(v) {
            sg.remove_node(v);
        }
    }
    let mut stack: Vec<VirtualRegister> = Vec::new();

    // --- Simplification Phase (pool-aware, incremental) ---
    // The naive version rescanned every remaining node and recomputed its pool-degree on
    // each removal -> O(V^2), which dominated compilation of large functions. Instead we
    // maintain each node's pool-degree incrementally: a worklist holds simplifiable
    // (degree < capacity) nodes, and a lazy max-heap supplies the highest-degree spill
    // candidate when nothing can be simplified. Same simplify/spill decisions, O((V+E) log V).
    use std::collections::BinaryHeap;

    // Deterministic node order (sg.nodes is a HashSet) so allocation is reproducible.
    let mut active_nodes: Vec<VirtualRegister> = sg.nodes.iter().copied().collect();
    active_nodes.sort_unstable();
    let total = active_nodes.len();

    let mut degree: HashMap<VirtualRegister, usize> = HashMap::with_capacity(total);
    for &v in &active_nodes {
        degree.insert(v, pool_degree(&sg, &v, secrecy_map));
    }

    let mut removed: HashSet<VirtualRegister> = HashSet::with_capacity(total);
    let mut queued: HashSet<VirtualRegister> = HashSet::with_capacity(total);
    let mut simplify: Vec<VirtualRegister> = Vec::new();
    // Lazy max-heap of (degree, vr); stale entries are skipped at pop time.
    let mut spill_heap: BinaryHeap<(usize, VirtualRegister)> = BinaryHeap::with_capacity(total);
    for &v in &active_nodes {
        let d = degree[&v];
        spill_heap.push((d, v));
        if d < pool_capacity(&v, k_clear, k_secret, secrecy_map) {
            queued.insert(v);
            simplify.push(v);
        }
    }

    let mut simplified = 0usize;
    while simplified < total {
        // Prefer a simplifiable node; otherwise spill the highest-degree remaining node.
        let victim = {
            let mut chosen = None;
            while let Some(cand) = simplify.pop() {
                if !removed.contains(&cand) {
                    chosen = Some(cand);
                    break;
                }
            }
            if chosen.is_none() {
                while let Some((d, cand)) = spill_heap.pop() {
                    if removed.contains(&cand) || degree[&cand] != d {
                        continue; // stale entry
                    }
                    chosen = Some(cand);
                    break;
                }
            }
            match chosen {
                Some(v) => v,
                None => break,
            }
        };

        stack.push(victim);
        removed.insert(victim);
        simplified += 1;

        // Removing `victim` lowers the pool-degree of its same-pool, still-active neighbors.
        let my_secret = secrecy_map[&victim];
        if let Some(neighbors) = sg.neighbors(&victim) {
            for &n in neighbors.iter() {
                if removed.contains(&n) || secrecy_map[&n] != my_secret {
                    continue;
                }
                let dn = degree.get_mut(&n).expect("active neighbor missing degree");
                if *dn > 0 {
                    *dn -= 1;
                }
                let new_d = *dn;
                spill_heap.push((new_d, n));
                if new_d < pool_capacity(&n, k_clear, k_secret, secrecy_map) && !queued.contains(&n)
                {
                    queued.insert(n);
                    simplify.push(n);
                }
            }
        }
    }

    // --- Assignment Phase ---
    let mut spilled_nodes = Vec::new();
    while let Some(vr) = stack.pop() {
        let requires_secret = *secrecy_map
            .get(&vr)
            .expect("missing secrecy_map entry for virtual register");

        // Define the pool of potential physical registers for this VR
        let allowed_regs_range = if requires_secret {
            k_clear..(k_clear + k_secret)
        } else {
            1..k_clear // Reserve physical R0 (0) for ABI return value
        };
        let mut available_colors_in_pool: HashSet<PhysicalRegister> =
            allowed_regs_range.map(PhysicalRegister).collect();

        // Check colors used by neighbors (in the original graph) that are already allocated
        if let Some(original_neighbors) = graph.neighbors(&vr) {
            for neighbor in original_neighbors {
                if let Some(physical_reg) = allocation.get(neighbor) {
                    available_colors_in_pool.remove(physical_reg);
                }
            }
        }

        // Assign the lowest available color from the allowed pool
        if let Some(&c) = available_colors_in_pool.iter().min() {
            allocation.insert(vr, c);
        } else {
            // No color available - this node needs to be spilled
            spilled_nodes.push(vr);
        }
    }

    if spilled_nodes.is_empty() {
        Ok(allocation)
    } else {
        Err(AllocationError::NeedsSpilling(spilled_nodes))
    }
}

// --- Linear-Scan Allocation ---

/// Linear-scan register allocation over single live intervals.
///
/// This is a memory-light O(V log V) alternative to graph coloring. It never materializes
/// an interference graph, which is essential for functions whose live-sets vastly exceed
/// the register file (e.g. a fully-inlined vectorized AES circuit with thousands of live
/// secret bits against 16 secret registers): there, the overlap graph is near-complete and
/// building it alone exhausts memory.
///
/// Two features make the surrounding object-spill loop converge in a couple of rounds
/// instead of growing without bound:
/// * `reserve` registers per pool are withheld from *spillable* virtual registers, leaving
///   headroom for the short-lived reload/store temporaries that spill lowering introduces.
/// * VRs in `unspillable` (those reload/store temporaries and the spill-object pointer) are
///   never chosen as spill victims and may use the reserved headroom, so once a value has
///   been spilled it never needs to be spilled again.
///
/// Returns the same contract as `color_graph`: a complete allocation, or `NeedsSpilling`
/// listing the virtual registers to spill.
pub fn linear_scan_partition(
    intervals: &HashMap<VirtualRegister, LiveInterval>,
    k_clear: usize,
    k_secret: usize,
    reserve: usize,
    secrecy_map: &HashMap<VirtualRegister, bool>,
    precolored: &HashMap<VirtualRegister, PhysicalRegister>,
    unspillable: &HashSet<VirtualRegister>,
) -> Result<Allocation, AllocationError> {
    use std::collections::BTreeSet;

    let secret_end = k_clear + k_secret;
    // Which allocatable pool a physical register belongs to, if any (physical R0 is the
    // reserved ABI return register and belongs to neither pool).
    let classify = |r: usize| -> Option<bool> {
        if (1..k_clear).contains(&r) {
            Some(false)
        } else if (k_clear..secret_end).contains(&r) {
            Some(true)
        } else {
            None
        }
    };

    // Precolored physical registers are reserved for the whole function (parameters are few;
    // this keeps the sweep provably interference-free without tracking fixed intervals).
    let reserved: BTreeSet<usize> = precolored.values().map(|p| p.0).collect();
    let mut free_clear: BTreeSet<usize> = (1..k_clear).filter(|r| !reserved.contains(r)).collect();
    let mut free_secret: BTreeSet<usize> = (k_clear..secret_end)
        .filter(|r| !reserved.contains(r))
        .collect();

    let mut order: Vec<(VirtualRegister, usize, usize)> = intervals
        .iter()
        .filter(|(vr, _)| !precolored.contains_key(vr))
        .map(|(&vr, iv)| (vr, iv.start, iv.end))
        .collect();
    order.sort_unstable_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

    let mut allocation: Allocation = precolored.clone();
    let mut spilled: Vec<VirtualRegister> = Vec::new();
    // Currently-assigned intervals: (end, reg, vr). Bounded by the register count, so the
    // linear scans of it below are cheap.
    let mut active: Vec<(usize, usize, VirtualRegister)> = Vec::new();

    let take_lowest = |pool: &mut BTreeSet<usize>| -> usize {
        let r = *pool.iter().next().expect("pool non-empty");
        pool.remove(&r);
        r
    };

    for &(vr, start, end) in &order {
        // Expire intervals that ended at or before this start; reclaim their registers.
        let mut i = 0;
        while i < active.len() {
            if active[i].0 <= start {
                let reg = active[i].1;
                match classify(reg) {
                    Some(true) => {
                        free_secret.insert(reg);
                    }
                    Some(false) => {
                        free_clear.insert(reg);
                    }
                    None => {}
                }
                active.swap_remove(i);
            } else {
                i += 1;
            }
        }

        let is_secret = *secrecy_map
            .get(&vr)
            .expect("missing secrecy_map entry for virtual register");
        let is_unspillable = unspillable.contains(&vr);
        let free_len = if is_secret {
            free_secret.len()
        } else {
            free_clear.len()
        };
        // Spillable VRs must leave `reserve` registers free for unspillable spill temps.
        let can_take = if is_unspillable {
            free_len > 0
        } else {
            free_len > reserve
        };

        if can_take {
            let reg = if is_secret {
                take_lowest(&mut free_secret)
            } else {
                take_lowest(&mut free_clear)
            };
            allocation.insert(vr, PhysicalRegister(reg));
            active.push((end, reg, vr));
            continue;
        }

        // No register available within budget: reuse a spillable active's register.
        let mut victim: Option<usize> = None;
        for (idx, a) in active.iter().enumerate() {
            if classify(a.1) == Some(is_secret)
                && !unspillable.contains(&a.2)
                && victim.is_none_or(|best: usize| a.0 > active[best].0)
            {
                victim = Some(idx);
            }
        }

        if is_unspillable {
            // An unspillable value must be placed; steal the furthest spillable register.
            match victim {
                Some(idx) => {
                    let stolen_reg = active[idx].1;
                    spilled.push(active[idx].2);
                    allocation.remove(&active[idx].2);
                    allocation.insert(vr, PhysicalRegister(stolen_reg));
                    active[idx] = (end, stolen_reg, vr);
                }
                None => return Err(AllocationError::PoolExhausted(vr, is_secret)),
            }
        } else {
            // Classic linear-scan heuristic: steal the furthest spillable register if it
            // outlives the current interval, otherwise spill the current interval.
            match victim {
                Some(idx) if active[idx].0 > end => {
                    let stolen_reg = active[idx].1;
                    spilled.push(active[idx].2);
                    allocation.remove(&active[idx].2);
                    allocation.insert(vr, PhysicalRegister(stolen_reg));
                    active[idx] = (end, stolen_reg, vr);
                }
                _ => spilled.push(vr),
            }
        }
    }

    if spilled.is_empty() {
        Ok(allocation)
    } else {
        Err(AllocationError::NeedsSpilling(spilled))
    }
}

// --- Instruction Rewriting ---

/// Helper to check if a physical register index is in the secret range
/// Rewrites instructions using virtual registers to use allocated physical registers.
pub fn rewrite_instructions(
    instructions: &[Instruction],
    allocation: &Allocation,
) -> Vec<Instruction> {
    use crate::register_allocator::InstructionRegisterAnalysis;
    let mut out: Vec<Instruction> = Vec::with_capacity(instructions.len());
    let mut last_was_call = false;
    for inst in instructions.iter() {
        match inst {
            // Special-case: right after a CALL, a MOV to capture return value.
            // If src is virtual register 0 in the IR, it was intended to mean ABI R0.
            // Emit MOV(dest_phys, 0) using physical R0 for the source.
            Instruction::MOV(dest_vr, src_vr) if last_was_call && *src_vr == 0 => {
                let dest_pr = allocation
                    .get(&VirtualRegister(*dest_vr))
                    .expect("Virtual register not found in allocation map during rewrite (MOV dest after CALL)")
                    .0;
                out.push(Instruction::MOV(dest_pr, 0));
                last_was_call = false; // handled
                continue;
            }
            _ => {}
        }
        // Default remapping path
        let rewritten = inst.remap_registers(allocation);
        last_was_call = matches!(inst, Instruction::CALL(_));
        out.push(rewritten);
    }
    out
}

// --- Helper trait for Instruction register analysis ---

/// Trait providing register allocation helper methods for Instructions
pub trait InstructionRegisterAnalysis {
    /// Returns a list of virtual registers defined (written to) by this instruction.
    fn defs(&self) -> Vec<VirtualRegister>;

    /// Returns a list of virtual registers used (read from) by this instruction.
    fn uses(&self) -> Vec<VirtualRegister>;

    /// Creates a new instruction with virtual registers replaced by physical registers.
    fn remap_registers(&self, allocation: &Allocation) -> Instruction;
}

impl InstructionRegisterAnalysis for Instruction {
    /// Returns a list of virtual registers defined (written to) by this instruction.
    fn defs(&self) -> Vec<VirtualRegister> {
        match self {
            Instruction::LD(r, _)
            | Instruction::LDI(r, _)
            | Instruction::MOV(r, _)
            | Instruction::ADD(r, _, _)
            | Instruction::SUB(r, _, _)
            | Instruction::MUL(r, _, _)
            | Instruction::DIV(r, _, _)
            | Instruction::MOD(r, _, _)
            | Instruction::AND(r, _, _)
            | Instruction::OR(r, _, _)
            | Instruction::XOR(r, _, _)
            | Instruction::NOT(r, _)
            | Instruction::SHL(r, _, _)
            | Instruction::SHR(r, _, _)
            | Instruction::LDS(r, _) => vec![VirtualRegister(*r)],
            // no defs here:
            Instruction::RET(_)
            | Instruction::PUSHARG(_)
            | Instruction::CMP(_, _)
            | Instruction::STS(_, _)
            | Instruction::JMP(_)
            | Instruction::JMPEQ(_)
            | Instruction::JMPNEQ(_)
            | Instruction::JMPLT(_)
            | Instruction::JMPGT(_)
            | Instruction::CALL(_)
            | Instruction::NOP => vec![], // These don't define registers in the typical sense
        }
    }

    /// Returns a list of virtual registers used (read from) by this instruction.
    fn uses(&self) -> Vec<VirtualRegister> {
        match self {
            Instruction::MOV(_, r_src)
            | Instruction::NOT(_, r_src)
            | Instruction::RET(r_src)
            | Instruction::PUSHARG(r_src)
            | Instruction::STS(_, r_src) => vec![VirtualRegister(*r_src)],
            Instruction::ADD(_, r1, r2)
            | Instruction::SUB(_, r1, r2)
            | Instruction::MUL(_, r1, r2)
            | Instruction::DIV(_, r1, r2)
            | Instruction::MOD(_, r1, r2)
            | Instruction::AND(_, r1, r2)
            | Instruction::OR(_, r1, r2)
            | Instruction::XOR(_, r1, r2)
            | Instruction::SHL(_, r1, r2)
            | Instruction::SHR(_, r1, r2)
            | Instruction::CMP(r1, r2) => vec![VirtualRegister(*r1), VirtualRegister(*r2)],
            Instruction::LD(_, _)
            | Instruction::LDI(_, _)
            | Instruction::LDS(_, _)
            | Instruction::JMP(_)
            | Instruction::JMPEQ(_)
            | Instruction::JMPNEQ(_)
            | Instruction::JMPLT(_)
            | Instruction::JMPGT(_)
            | Instruction::CALL(_)
            | Instruction::NOP => vec![], // These don't use registers in the typical sense
        }
    }

    /// Creates a new instruction with virtual registers replaced by physical registers.
    /// Panics if a virtual register in the instruction is not found in the allocation map.
    fn remap_registers(&self, allocation: &Allocation) -> Instruction {
        let map_reg = |vr: usize| {
            allocation
                .get(&VirtualRegister(vr))
                .expect("Virtual register not found in allocation map during rewrite")
                .0
        }; // Get the usize physical register index

        match *self {
            Instruction::LD(vr_dest, offset) => Instruction::LD(map_reg(vr_dest), offset),
            Instruction::LDI(vr_dest, ref val) => Instruction::LDI(map_reg(vr_dest), val.clone()),
            Instruction::MOV(vr_dest, vr_src) => {
                Instruction::MOV(map_reg(vr_dest), map_reg(vr_src))
            }
            Instruction::ADD(vr_dest, vr1, vr2) => {
                Instruction::ADD(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::SUB(vr_dest, vr1, vr2) => {
                Instruction::SUB(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::MUL(vr_dest, vr1, vr2) => {
                Instruction::MUL(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::DIV(vr_dest, vr1, vr2) => {
                Instruction::DIV(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::MOD(vr_dest, vr1, vr2) => {
                Instruction::MOD(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::AND(vr_dest, vr1, vr2) => {
                Instruction::AND(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::OR(vr_dest, vr1, vr2) => {
                Instruction::OR(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::XOR(vr_dest, vr1, vr2) => {
                Instruction::XOR(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::NOT(vr_dest, vr_src) => {
                Instruction::NOT(map_reg(vr_dest), map_reg(vr_src))
            }
            Instruction::SHL(vr_dest, vr1, vr2) => {
                Instruction::SHL(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::SHR(vr_dest, vr1, vr2) => {
                Instruction::SHR(map_reg(vr_dest), map_reg(vr1), map_reg(vr2))
            }
            Instruction::CMP(vr1, vr2) => Instruction::CMP(map_reg(vr1), map_reg(vr2)),
            Instruction::RET(vr_src) => Instruction::RET(map_reg(vr_src)),
            Instruction::PUSHARG(vr_src) => Instruction::PUSHARG(map_reg(vr_src)),
            // Spill-slot ops: remap the register operand, leave the slot index as-is.
            Instruction::LDS(vr_dest, slot) => Instruction::LDS(map_reg(vr_dest), slot),
            Instruction::STS(slot, vr_src) => Instruction::STS(slot, map_reg(vr_src)),
            // Instructions without registers remain the same
            Instruction::JMP(ref label) => Instruction::JMP(label.clone()),
            Instruction::JMPEQ(ref label) => Instruction::JMPEQ(label.clone()),
            Instruction::JMPNEQ(ref label) => Instruction::JMPNEQ(label.clone()),
            Instruction::JMPLT(ref label) => Instruction::JMPLT(label.clone()),
            Instruction::JMPGT(ref label) => Instruction::JMPGT(label.clone()),
            Instruction::CALL(ref name) => Instruction::CALL(name.clone()),
            Instruction::NOP => Instruction::NOP,
        }
    }
}
