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

/// Dense allocation result, indexed by `VirtualRegister.0` (VR ids are minted
/// sequentially by codegen, so the index space has no holes worth hashing over).
pub type DenseAllocation = Vec<Option<PhysicalRegister>>;

/// Sentinel meaning "no unspillable virtual registers" for the
/// `unspillable_start` threshold parameter of `linear_scan_partition`.
pub const NO_UNSPILLABLE: usize = usize::MAX;

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
/// Legacy map-returning wrapper around `analyze_liveness_cfg_dense`.
pub fn analyze_liveness_cfg_with_liveins(
    instructions: &[Instruction],
    labels: &HashMap<String, usize>,
    live_in: &[VirtualRegister],
) -> HashMap<VirtualRegister, LiveInterval> {
    analyze_liveness_cfg_dense(instructions, labels, live_in)
        .iter()
        .enumerate()
        .filter_map(|(id, iv)| iv.map(|iv| (VirtualRegister(id), iv)))
        .collect()
}

/// Sentinel for an empty operand slot in `InstOps`.
const NO_REG: u32 = u32::MAX;

/// Per-instruction operands in a fixed shape: at most two uses and one def
/// (the invariant `uses()`/`defs()` encode with their `vec!` literals). Slots
/// hold raw VR ids first, then are remapped in place to dense indices.
#[derive(Clone, Copy)]
struct InstOps {
    uses: [u32; 2],
    def: u32,
}

/// Allocation-free mirror of `defs()`: the destination register, if any.
/// Must stay in sync with `InstructionRegisterAnalysis::defs`.
#[inline]
pub fn def_reg(inst: &Instruction) -> Option<usize> {
    match inst {
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
        | Instruction::LDS(r, _) => Some(*r),
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
        | Instruction::NOP => None,
    }
}

/// Allocation-free mirror of `uses()`: up to two source registers, in the same
/// operand order `uses()` returns them. Must stay in sync with
/// `InstructionRegisterAnalysis::uses`.
#[inline]
pub fn use_regs(inst: &Instruction) -> [Option<usize>; 2] {
    match inst {
        Instruction::MOV(_, r_src)
        | Instruction::NOT(_, r_src)
        | Instruction::RET(r_src)
        | Instruction::PUSHARG(r_src)
        | Instruction::STS(_, r_src) => [Some(*r_src), None],
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
        | Instruction::CMP(r1, r2) => [Some(*r1), Some(*r2)],
        Instruction::LD(_, _)
        | Instruction::LDI(_, _)
        | Instruction::LDS(_, _)
        | Instruction::JMP(_)
        | Instruction::JMPEQ(_)
        | Instruction::JMPNEQ(_)
        | Instruction::JMPLT(_)
        | Instruction::JMPGT(_)
        | Instruction::CALL(_)
        | Instruction::NOP => [None, None],
    }
}

/// CFG-based liveness with explicit labels (block successors) and live-ins.
/// Builds basic blocks, runs iterative dataflow to compute live-in/out, then per-instruction liveness,
/// and finally collapses to single intervals per virtual register.
///
/// Returns the intervals as a dense vector indexed by `VirtualRegister.0` (`None`
/// for ids that never appear), so downstream consumers never hash a VR.
pub fn analyze_liveness_cfg_dense(
    instructions: &[Instruction],
    labels: &HashMap<String, usize>,
    live_in: &[VirtualRegister],
) -> Vec<Option<LiveInterval>> {
    let n = instructions.len();
    // Early exit
    if n == 0 {
        return Vec::new();
    }

    // Decode each instruction's operands exactly once into a fixed-shape record
    // (`uses()`/`defs()` allocate a Vec per call), tracking the largest VR id in
    // the same pass. Each VR then gets a dense index so liveness can run over
    // fixed-size bitsets (Vec<u64>) instead of cloning HashSets — the per-instruction
    // HashSet clones were the O(n * live_set) blowup that made large functions
    // (e.g. the vectorized AES circuit) take minutes to compile.
    let mut inst_ops: Vec<InstOps> = Vec::with_capacity(n);
    let mut max_vr: Option<usize> = None;
    for inst in instructions.iter() {
        let mut ops = InstOps {
            uses: [NO_REG; 2],
            def: NO_REG,
        };
        for (slot, u) in use_regs(inst).into_iter().flatten().enumerate() {
            max_vr = Some(max_vr.map_or(u, |m| m.max(u)));
            ops.uses[slot] = u as u32;
        }
        if let Some(d) = def_reg(inst) {
            max_vr = Some(max_vr.map_or(d, |m| m.max(d)));
            ops.def = d as u32;
        }
        inst_ops.push(ops);
    }
    for &vr in live_in {
        max_vr = Some(max_vr.map_or(vr.0, |m| m.max(vr.0)));
    }

    // Dense, deterministic indexing without hashing every virtual register. VR
    // ids are compiler-generated usize values, so a direct seen table makes this
    // setup O(instructions + uses/defs + max_vr) instead of spending much of
    // large-function compile time in HashSet growth and SipHash.
    let Some(max_vr) = max_vr else {
        return Vec::new();
    };
    // Ids are stored in u32 slots with NO_REG as the sentinel.
    assert!(max_vr < NO_REG as usize, "virtual register id overflow");
    let mut seen = vec![false; max_vr.saturating_add(1)];
    for ops in &inst_ops {
        for &u in &ops.uses {
            if u != NO_REG {
                seen[u as usize] = true;
            }
        }
        if ops.def != NO_REG {
            seen[ops.def as usize] = true;
        }
    }
    for &vr in live_in {
        seen[vr.0] = true;
    }
    let mut vrs: Vec<VirtualRegister> = Vec::with_capacity(seen.iter().filter(|&&b| b).count());
    let mut vr_index_by_id: Vec<u32> = vec![u32::MAX; seen.len()];
    for (id, is_seen) in seen.into_iter().enumerate() {
        if is_seen {
            let dense = vrs.len() as u32;
            vrs.push(VirtualRegister(id));
            vr_index_by_id[id] = dense;
        }
    }
    let num_vrs = vrs.len();

    // Remap the operand records from raw ids to dense indices in place, so the
    // hot loops below never re-decode an instruction or hash a VirtualRegister.
    for ops in &mut inst_ops {
        for u in &mut ops.uses {
            if *u != NO_REG {
                *u = vr_index_by_id[*u as usize];
            }
        }
        if ops.def != NO_REG {
            ops.def = vr_index_by_id[ops.def as usize];
        }
    }

    // Bitset over `words` u64 lanes, one bit per dense VR index.
    let words = num_vrs.div_ceil(64);
    #[inline]
    fn bit_set(bits: &mut [u64], i: u32) {
        bits[(i >> 6) as usize] |= 1u64 << (i & 63);
    }

    // 1) Determine basic block boundaries
    let mut inst2block = vec![0usize; n];
    for &idx in labels.values() {
        if idx < n {
            inst2block[idx] = 1;
        }
    }
    for (i, instruction) in instructions.iter().enumerate() {
        if matches!(
            instruction,
            Instruction::JMP(_)
                | Instruction::JMPEQ(_)
                | Instruction::JMPNEQ(_)
                | Instruction::JMPLT(_)
                | Instruction::JMPGT(_)
                | Instruction::RET(_)
        ) && i + 1 < n
        {
            inst2block[i + 1] = 1;
        }
    }
    let mut starts = vec![0];
    for (i, block) in inst2block.iter_mut().enumerate() {
        if i != 0 && *block != 0 {
            starts.push(i);
        }
        *block = starts.len() - 1;
    }

    struct BlockInfo {
        start: usize,
        end: usize, // exclusive
        succs: [usize; 2],
        successor_count: usize,
        use_bits: std::ops::Range<usize>, // slice of shared nonzero use words
        def_bits: std::ops::Range<usize>, // slice of shared nonzero def words
    }

    let mut blocks: Vec<BlockInfo> = Vec::with_capacity(starts.len());
    for (bi, &s) in starts.iter().enumerate() {
        let e = starts.get(bi + 1).copied().unwrap_or(n);
        blocks.push(BlockInfo {
            start: s,
            end: e,
            succs: [0; 2],
            successor_count: 0,
            use_bits: 0..0,
            def_bits: 0..0,
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
                    block.succs[block.successor_count] = t;
                    block.successor_count += 1;
                }
            }
            Instruction::JMPEQ(lbl)
            | Instruction::JMPNEQ(lbl)
            | Instruction::JMPLT(lbl)
            | Instruction::JMPGT(lbl) => {
                if let Some(t) = label_to_block(lbl) {
                    block.succs[block.successor_count] = t;
                    block.successor_count += 1;
                }
                // fallthrough
                if let Some(next_start) = starts.get(bi + 1).copied() {
                    if next_start < n {
                        block.succs[block.successor_count] = bi + 1;
                        block.successor_count += 1;
                    }
                }
            }
            Instruction::RET(_) => { /* no successors */ }
            _ => {
                // fallthrough
                if let Some(_next) = starts.get(bi + 1) {
                    block.succs[block.successor_count] = bi + 1;
                    block.successor_count += 1;
                }
            }
        }
        // Dedup succs
        if block.successor_count == 2 && block.succs[0] == block.succs[1] {
            block.successor_count = 1;
        }
    }

    // Store only nonzero words per block. Dense scratch is shared across all
    // blocks; clearing/extracting it visits only touched words.
    fn add_words(input: &[(usize, u64)], bits: &mut [u64], touched: &mut Vec<usize>) {
        for &(word, mask) in input {
            if bits[word] == 0 {
                touched.push(word);
            }
            bits[word] |= mask;
        }
    }
    fn take_words(bits: &mut [u64], touched: &mut Vec<usize>, out: &mut Vec<(usize, u64)>) {
        touched.sort_unstable();
        touched.dedup(); // a kill followed by a use may touch the same word twice
        out.clear();
        for word in touched.drain(..) {
            let mask = std::mem::take(&mut bits[word]);
            if mask != 0 {
                out.push((word, mask));
            }
        }
    }
    let mut new_out = vec![0u64; words];
    let mut defs = vec![0u64; words];
    let mut touched_words = Vec::new();
    let mut def_words = Vec::new();
    let mut block_uses = Vec::new();
    let mut block_defs = Vec::new();
    let mut extracted = Vec::new();
    for b in &mut blocks {
        for &ops in &inst_ops[b.start..b.end] {
            for &u in &ops.uses {
                if u == NO_REG {
                    continue;
                }
                let word = (u >> 6) as usize;
                if (defs[word] >> (u & 63)) & 1 == 0 {
                    if new_out[word] == 0 {
                        touched_words.push(word);
                    }
                    bit_set(&mut new_out, u);
                }
            }
            if ops.def != NO_REG {
                let word = (ops.def >> 6) as usize;
                if defs[word] == 0 {
                    def_words.push(word);
                }
                bit_set(&mut defs, ops.def);
            }
        }
        take_words(&mut new_out, &mut touched_words, &mut extracted);
        let start = block_uses.len();
        block_uses.extend_from_slice(&extracted);
        b.use_bits = start..block_uses.len();
        take_words(&mut defs, &mut def_words, &mut extracted);
        let start = block_defs.len();
        block_defs.extend_from_slice(&extracted);
        b.def_bits = start..block_defs.len();
    }
    drop(defs);
    drop(def_words);
    drop(extracted);

    // 4) Only revisit predecessors whose successor live-in changed. The initial
    // reverse-order pass settles ordinary forward control flow in one visit.
    // Predecessors use a compact CSR index, not one allocation per block.
    let mut pred_offsets = vec![0usize; blocks.len() + 1];
    for block in &blocks {
        for &successor in &block.succs[..block.successor_count] {
            pred_offsets[successor + 1] += 1;
        }
    }
    for i in 1..pred_offsets.len() {
        pred_offsets[i] += pred_offsets[i - 1];
    }
    let mut predecessors = vec![0usize; *pred_offsets.last().unwrap()];
    let mut cursor = pred_offsets.clone();
    for (bi, block) in blocks.iter().enumerate() {
        for &successor in &block.succs[..block.successor_count] {
            predecessors[cursor[successor]] = bi;
            cursor[successor] += 1;
        }
    }
    drop(cursor);

    let entry_block = inst2block[0];
    for &vr in live_in {
        let index = vr_index_by_id[vr.0];
        let word = (index >> 6) as usize;
        if new_out[word] == 0 {
            touched_words.push(word);
        }
        bit_set(&mut new_out, index);
    }
    let mut entry_seed = Vec::new();
    take_words(&mut new_out, &mut touched_words, &mut entry_seed);
    let mut live_in_b = vec![Vec::new(); blocks.len()];
    live_in_b[entry_block] = entry_seed.clone();
    let mut next = Vec::new();
    let mut work: Vec<_> = (0..blocks.len()).collect();
    let mut queued = vec![true; blocks.len()];
    while let Some(bi) = work.pop() {
        queued[bi] = false;
        for &successor in &blocks[bi].succs[..blocks[bi].successor_count] {
            add_words(&live_in_b[successor], &mut new_out, &mut touched_words);
        }
        for &(word, mask) in &block_defs[blocks[bi].def_bits.clone()] {
            new_out[word] &= !mask;
        }
        add_words(
            &block_uses[blocks[bi].use_bits.clone()],
            &mut new_out,
            &mut touched_words,
        );
        if bi == entry_block {
            add_words(&entry_seed, &mut new_out, &mut touched_words);
        }
        take_words(&mut new_out, &mut touched_words, &mut next);
        if next != live_in_b[bi] {
            std::mem::swap(&mut next, &mut live_in_b[bi]);
            for &pred in &predecessors[pred_offsets[bi]..pred_offsets[bi + 1]] {
                if !queued[pred] {
                    queued[pred] = true;
                    work.push(pred);
                }
            }
        }
    }
    drop(block_uses);
    drop(block_defs);
    drop(new_out);
    drop(next);
    drop(touched_words);
    // Live-out is a union of successor live-ins; reconstruct it on demand
    // below instead of retaining another blocks × registers bit matrix.
    drop(predecessors);
    drop(pred_offsets);
    drop(work);
    drop(queued);

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
    // Last def per VR: a def is a WRITE to the assigned physical register, so
    // the interval must cover it even when no use follows (a dead tail store —
    // e.g. a reassignment of a variable whose reads were all optimized away).
    // Without this, the register given to a dead def can simultaneously be
    // assigned to a live value, and the dead store CLOBBERS it at runtime (the
    // legacy `analyze_liveness_with_liveins` counts defs as uses for exactly
    // this reason).
    let mut def_last = vec![usize::MAX; num_vrs];
    for (i, ops) in inst_ops.iter().enumerate() {
        if ops.def != NO_REG {
            let di = ops.def as usize;
            if i < def_first[di] {
                def_first[di] = i;
            }
            if def_last[di] == usize::MAX || i > def_last[di] {
                def_last[di] = i;
            }
        }
    }

    let mut end_idx = vec![0usize; num_vrs];
    // Sparse live set: `present[vi]` is membership; `touched` records indices set
    // during the current block so they can be reset in O(touched) before the next.
    let mut present = vec![false; num_vrs];
    let mut touched: Vec<usize> = Vec::new();
    for block in &blocks {
        for &vi in &touched {
            present[vi] = false;
        }
        touched.clear();
        // Seed with the block's live-out. Its last instruction is at index
        // block.end-1, so the highest live-out index for these VRs is block.end-1
        // (→ end_idx = block.end), matching the dense walk's `i + 1` at that index.
        for &successor in &block.succs[..block.successor_count] {
            for &(w, word) in &live_in_b[successor] {
                let mut x = word;
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
        }
        for i in (block.start..block.end).rev() {
            // `present` is live_out_inst[i]. Step to live_in_inst[i] = (live − defs) ∪ uses.
            let ops = inst_ops[i];
            if ops.def != NO_REG {
                present[ops.def as usize] = false;
            }
            for &u in &ops.uses {
                if u == NO_REG {
                    continue;
                }
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

    let mut intervals: Vec<Option<LiveInterval>> = vec![None; max_vr + 1];
    for (vi, &vr) in vrs.iter().enumerate() {
        // A VR with no def is a function live-in (parameter): live from entry, so
        // start at 0 — a conservative interval that is never too short.
        let start = if def_first[vi] != usize::MAX {
            def_first[vi]
        } else {
            0
        };
        let mut end = end_idx[vi];
        if def_last[vi] != usize::MAX {
            // Cover every def point, including dead tail stores (see above).
            let d = def_last[vi];
            if end < d + 1 {
                end = d + 1;
            }
        }
        if end <= start {
            end = start + 1;
        }
        intervals[vr.0] = Some(LiveInterval { start, end });
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

    // Start with precolored allocation (e.g., ABI-fixed registers like parameters)
    let mut allocation: Allocation =
        HashMap::with_capacity(graph.nodes.len().max(precolored.len()));
    allocation.extend(precolored.iter().map(|(&vr, &pr)| (vr, pr)));
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
/// * Unspillable VRs (those reload/store temporaries and the spill-object pointer) are
///   never chosen as spill victims and may use the reserved headroom, so once a value has
///   been spilled it never needs to be spilled again.
///
/// Returns the same contract as `color_graph`: a complete allocation, or `NeedsSpilling`
/// listing the virtual registers to spill.
///
/// `intervals` and `secrecy` are dense, indexed by `VirtualRegister.0` (see
/// `analyze_liveness_cfg_dense`). `unspillable_start` is a threshold: every VR
/// with `id >= unspillable_start` is unspillable (spill lowering mints its
/// scratch registers as one contiguous id range at the top of the id space);
/// pass `NO_UNSPILLABLE` when there are none.
pub fn linear_scan_partition(
    intervals: &[Option<LiveInterval>],
    k_clear: usize,
    k_secret: usize,
    reserve: usize,
    secrecy: &[bool],
    precolored: &HashMap<VirtualRegister, PhysicalRegister>,
    unspillable_start: usize,
) -> Result<DenseAllocation, AllocationError> {
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

    // Candidate list in (start, vr) order via a counting sort by interval start:
    // starts are instruction indices, and iterating VR ids ascending within each
    // start bucket reproduces the `sort_unstable_by((start, vr))` order exactly
    // (each interval's vr is unique, so the tie-break key is the iteration order).
    let mut is_precolored = vec![false; intervals.len()];
    for vr in precolored.keys() {
        if vr.0 < is_precolored.len() {
            is_precolored[vr.0] = true;
        }
    }
    let mut max_start = 0usize;
    let mut total = 0usize;
    for (id, iv) in intervals.iter().enumerate() {
        if let Some(iv) = iv {
            if !is_precolored[id] {
                total += 1;
                max_start = max_start.max(iv.start);
            }
        }
    }
    // offsets[s+1] counts intervals starting at s; after the prefix sum, offsets[s]
    // is the next write position for start s.
    let mut offsets = vec![0u32; max_start + 2];
    for (id, iv) in intervals.iter().enumerate() {
        if let Some(iv) = iv {
            if !is_precolored[id] {
                offsets[iv.start + 1] += 1;
            }
        }
    }
    for s in 1..offsets.len() {
        offsets[s] += offsets[s - 1];
    }
    let mut order: Vec<(VirtualRegister, usize, usize)> = vec![(VirtualRegister(0), 0, 0); total];
    for (id, iv) in intervals.iter().enumerate() {
        if let Some(iv) = iv {
            if !is_precolored[id] {
                let slot = &mut offsets[iv.start];
                order[*slot as usize] = (VirtualRegister(id), iv.start, iv.end);
                *slot += 1;
            }
        }
    }

    let alloc_len = intervals
        .len()
        .max(precolored.keys().map(|vr| vr.0 + 1).max().unwrap_or(0));
    let mut allocation: DenseAllocation = vec![None; alloc_len];
    for (&vr, &pr) in precolored.iter() {
        allocation[vr.0] = Some(pr);
    }
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

        let is_secret = *secrecy
            .get(vr.0)
            .expect("missing secrecy entry for virtual register");
        let is_unspillable = vr.0 >= unspillable_start;
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
            allocation[vr.0] = Some(PhysicalRegister(reg));
            active.push((end, reg, vr));
            continue;
        }

        // No register available within budget: reuse a spillable active's register.
        let mut victim: Option<usize> = None;
        for (idx, a) in active.iter().enumerate() {
            if classify(a.1) == Some(is_secret)
                && a.2 .0 < unspillable_start
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
                    allocation[active[idx].2 .0] = None;
                    allocation[vr.0] = Some(PhysicalRegister(stolen_reg));
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
                    allocation[active[idx].2 .0] = None;
                    allocation[vr.0] = Some(PhysicalRegister(stolen_reg));
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
    let map_reg = |vr: usize| {
        allocation
            .get(&VirtualRegister(vr))
            .expect("Virtual register not found in allocation map during rewrite")
            .0
    };
    rewrite_instructions_with(instructions, &map_reg)
}

/// Dense-allocation variant of `rewrite_instructions` (see `DenseAllocation`).
pub fn rewrite_instructions_dense(
    instructions: &[Instruction],
    allocation: &[Option<PhysicalRegister>],
) -> Vec<Instruction> {
    let map_reg = |vr: usize| {
        allocation
            .get(vr)
            .copied()
            .flatten()
            .expect("Virtual register not found in allocation map during rewrite")
            .0
    };
    rewrite_instructions_with(instructions, &map_reg)
}

fn rewrite_instructions_with(
    instructions: &[Instruction],
    map_reg: &dyn Fn(usize) -> usize,
) -> Vec<Instruction> {
    let mut out: Vec<Instruction> = Vec::with_capacity(instructions.len());
    let mut last_was_call = false;
    for inst in instructions.iter() {
        match inst {
            // Special-case: right after a CALL, a MOV to capture return value.
            // If src is virtual register 0 in the IR, it was intended to mean ABI R0.
            // Emit MOV(dest_phys, 0) using physical R0 for the source.
            Instruction::MOV(dest_vr, src_vr) if last_was_call && *src_vr == 0 => {
                let dest_pr = map_reg(*dest_vr);
                out.push(Instruction::MOV(dest_pr, 0));
                last_was_call = false; // handled
                continue;
            }
            _ => {}
        }
        // Default remapping path
        let rewritten = remap_instruction_with(inst, map_reg);
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
        remap_instruction_with(self, &map_reg)
    }
}

/// Rebuilds `inst` with every register operand passed through `map_reg`.
fn remap_instruction_with(inst: &Instruction, map_reg: &dyn Fn(usize) -> usize) -> Instruction {
    match *inst {
        Instruction::LD(vr_dest, offset) => Instruction::LD(map_reg(vr_dest), offset),
        Instruction::LDI(vr_dest, ref val) => Instruction::LDI(map_reg(vr_dest), val.clone()),
        Instruction::MOV(vr_dest, vr_src) => Instruction::MOV(map_reg(vr_dest), map_reg(vr_src)),
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
        Instruction::NOT(vr_dest, vr_src) => Instruction::NOT(map_reg(vr_dest), map_reg(vr_src)),
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

#[cfg(test)]
mod worklist_tests {
    use super::*;

    // Independent instruction-level fixed point, deliberately using sets and
    // exhaustive sweeps. This checks the optimized block worklist and interval
    // extraction on loops, disconnected code, joins, and duplicate successors.
    fn reference(
        code: &[Instruction],
        labels: &HashMap<String, usize>,
        seeds: &[VirtualRegister],
    ) -> Vec<Option<LiveInterval>> {
        let mut incoming = vec![HashSet::<usize>::new(); code.len()];
        let mut outgoing = incoming.clone();
        loop {
            let mut changed = false;
            for i in (0..code.len()).rev() {
                let mut successors = Vec::new();
                match &code[i] {
                    Instruction::JMP(label) => successors.push(labels[label]),
                    Instruction::JMPEQ(label)
                    | Instruction::JMPNEQ(label)
                    | Instruction::JMPLT(label)
                    | Instruction::JMPGT(label) => {
                        successors.push(labels[label]);
                        if i + 1 < code.len() {
                            successors.push(i + 1);
                        }
                    }
                    Instruction::RET(_) => {}
                    _ => {
                        if i + 1 < code.len() {
                            successors.push(i + 1);
                        }
                    }
                }
                let out: HashSet<_> = successors
                    .iter()
                    .flat_map(|&s| incoming[s].iter().copied())
                    .collect();
                let mut input = out.clone();
                if let Some(def) = def_reg(&code[i]) {
                    input.remove(&def);
                }
                input.extend(use_regs(&code[i]).into_iter().flatten());
                if i == 0 {
                    input.extend(seeds.iter().map(|r| r.0));
                }
                changed |= incoming[i] != input || outgoing[i] != out;
                incoming[i] = input;
                outgoing[i] = out;
            }
            if !changed {
                break;
            }
        }
        let mut regs: HashSet<_> = seeds.iter().map(|r| r.0).collect();
        for inst in code {
            regs.extend(use_regs(inst).into_iter().flatten());
            regs.extend(def_reg(inst));
        }
        let mut result = vec![None; regs.iter().copied().max().map_or(0, |r| r + 1)];
        for r in regs {
            let defs: Vec<_> = code
                .iter()
                .enumerate()
                .filter_map(|(i, inst)| (def_reg(inst) == Some(r)).then_some(i))
                .collect();
            let start = defs.first().copied().unwrap_or(0);
            let end = outgoing
                .iter()
                .rposition(|out| out.contains(&r))
                .map_or(0, |i| i + 1)
                // Reads occur before the instruction's write. Include uses at
                // disconnected block entries even without a live predecessor.
                .max(
                    code.iter()
                        .rposition(|inst| use_regs(inst).contains(&Some(r)))
                        .unwrap_or(0),
                )
                .max(defs.last().map_or(0, |i| i + 1))
                .max(start + 1);
            result[r] = Some(LiveInterval { start, end });
        }
        result
    }

    #[test]
    fn worklist_intervals_match_instruction_fixed_point() {
        for seed in 0..32 {
            let mut code = Vec::new();
            let mut labels = HashMap::new();
            for i in 0..260 {
                let a = (i * 7 + seed) % 193;
                let b = (i * 3 + seed) % 193;
                let target = if i % 2 == 0 {
                    (i + 1) % 260
                } else {
                    (i * 13 + seed * 7) % 260
                };
                let label = format!("label_{target}");
                let inst = if i % 7 == 0 {
                    labels.insert(label.clone(), target);
                    Instruction::JMPEQ(label)
                } else if i % 11 == 0 {
                    labels.insert(label.clone(), target);
                    Instruction::JMP(label)
                } else if i % 17 == 0 {
                    Instruction::RET(a)
                } else {
                    Instruction::ADD(a, b, (b + 1) % 193)
                };
                code.push(inst);
            }
            let seeds = [VirtualRegister(1), VirtualRegister(320)];
            assert_eq!(
                analyze_liveness_cfg_dense(&code, &labels, &seeds),
                reference(&code, &labels, &seeds),
                "graph {seed}"
            );
        }
    }
}
