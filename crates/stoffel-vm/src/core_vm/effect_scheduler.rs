use crate::error::VmResult;
use crate::net::mpc_engine::AsyncMpcEngine;
use crate::vm_state::{CallStackCheckpoint, VMState, VmEffectKind, VmExecutionBudget, VmRunSlice};
use std::time::{Duration, Instant};
use stoffel_vm_types::core_types::Value;

const DEFAULT_LOCAL_INSTRUCTION_BUDGET: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AsyncEffectScheduler {
    local_budget: VmExecutionBudget,
}

impl Default for AsyncEffectScheduler {
    fn default() -> Self {
        Self::new(DEFAULT_LOCAL_INSTRUCTION_BUDGET)
    }
}

impl AsyncEffectScheduler {
    pub(crate) const fn new(local_instruction_budget: usize) -> Self {
        Self {
            local_budget: VmExecutionBudget::max_instructions(local_instruction_budget),
        }
    }

    pub(crate) async fn execute_to_depth<E: AsyncMpcEngine + ?Sized>(
        self,
        state: &mut VMState,
        checkpoint: CallStackCheckpoint,
        engine: &E,
    ) -> VmResult<Value> {
        let mut engine_identity_checked = false;
        let mut progress = AsyncMpcProgress::from_env();

        loop {
            match state.run_until_effect_or_budget_to_depth(checkpoint, self.local_budget)? {
                VmRunSlice::Complete(value) => {
                    progress.report_final();
                    return Ok(value);
                }
                VmRunSlice::BudgetExhausted => {
                    progress.record_budget_yield();
                    tokio::task::yield_now().await;
                }
                VmRunSlice::Yield(effect) => {
                    if !engine_identity_checked {
                        state.ensure_async_engine_matches(engine)?;
                        engine_identity_checked = true;
                    }
                    progress.record_effect(effect.summary());
                    let completed = effect.execute(engine).await?;
                    state.apply_completed_vm_effect(completed)?;
                }
            }
        }
    }
}

#[derive(Debug)]
struct AsyncMpcProgress {
    interval: Option<Duration>,
    started_at: Instant,
    last_report_at: Instant,
    budget_yields: u64,
    effects: u64,
    inputs: u64,
    multiplies: u64,
    boolean_bits: u64,
    opens: u64,
    builtin_inputs: u64,
    builtin_muls: u64,
    builtin_batch_muls: u64,
    builtin_batch_mul_items: u64,
    builtin_opens: u64,
    builtin_batch_opens: u64,
    builtin_batch_open_items: u64,
    builtin_other: u64,
}

impl AsyncMpcProgress {
    fn from_env() -> Self {
        let now = Instant::now();
        let interval = std::env::var("STOFFEL_VM_MPC_PROGRESS_INTERVAL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_secs);
        Self {
            interval,
            started_at: now,
            last_report_at: now,
            budget_yields: 0,
            effects: 0,
            inputs: 0,
            multiplies: 0,
            boolean_bits: 0,
            opens: 0,
            builtin_inputs: 0,
            builtin_muls: 0,
            builtin_batch_muls: 0,
            builtin_batch_mul_items: 0,
            builtin_opens: 0,
            builtin_batch_opens: 0,
            builtin_batch_open_items: 0,
            builtin_other: 0,
        }
    }

    fn record_budget_yield(&mut self) {
        self.budget_yields = self.budget_yields.saturating_add(1);
        self.report_if_due();
    }

    fn record_effect(&mut self, summary: crate::vm_state::VmEffectSummary) {
        self.effects = self.effects.saturating_add(1);
        let items = u64::try_from(summary.items).unwrap_or(u64::MAX);
        match summary.kind {
            VmEffectKind::Input => self.inputs = self.inputs.saturating_add(1),
            VmEffectKind::Multiply => self.multiplies = self.multiplies.saturating_add(1),
            VmEffectKind::BooleanBit => self.boolean_bits = self.boolean_bits.saturating_add(1),
            VmEffectKind::Open => self.opens = self.opens.saturating_add(1),
            VmEffectKind::BuiltinInput => {
                self.builtin_inputs = self.builtin_inputs.saturating_add(1)
            }
            VmEffectKind::BuiltinMul => self.builtin_muls = self.builtin_muls.saturating_add(1),
            VmEffectKind::BuiltinBatchMul => {
                self.builtin_batch_muls = self.builtin_batch_muls.saturating_add(1);
                self.builtin_batch_mul_items = self.builtin_batch_mul_items.saturating_add(items);
            }
            VmEffectKind::BuiltinOpen => self.builtin_opens = self.builtin_opens.saturating_add(1),
            VmEffectKind::BuiltinBatchOpen => {
                self.builtin_batch_opens = self.builtin_batch_opens.saturating_add(1);
                self.builtin_batch_open_items = self.builtin_batch_open_items.saturating_add(items);
            }
            VmEffectKind::BuiltinOther => self.builtin_other = self.builtin_other.saturating_add(1),
        }
        self.report_if_due();
    }

    fn report_if_due(&mut self) {
        let Some(interval) = self.interval else {
            return;
        };
        if self.last_report_at.elapsed() >= interval {
            self.report("progress");
            self.last_report_at = Instant::now();
        }
    }

    fn report_final(&self) {
        if self.interval.is_some() {
            self.report("complete");
        }
    }

    fn report(&self, label: &str) {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let effect_rate = if elapsed > 0.0 {
            self.effects as f64 / elapsed
        } else {
            0.0
        };
        eprintln!(
            "[vm async mpc {label}] elapsed={:.1}s effects={} rate={:.2}/s budget_yields={} input={} mul={} bool={} open={} builtin_input={} builtin_mul={} batch_mul={} batch_mul_items={} builtin_open={} batch_open={} batch_open_items={} builtin_other={}",
            elapsed,
            self.effects,
            effect_rate,
            self.budget_yields,
            self.inputs,
            self.multiplies,
            self.boolean_bits,
            self.opens,
            self.builtin_inputs,
            self.builtin_muls,
            self.builtin_batch_muls,
            self.builtin_batch_mul_items,
            self.builtin_opens,
            self.builtin_batch_opens,
            self.builtin_batch_open_items,
            self.builtin_other,
        );
    }
}
