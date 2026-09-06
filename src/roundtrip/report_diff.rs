//! Strict, reporting-only logical-line diff support for review.
//! Upstream attribution: based on the implementation by Brandon Williams.
//! The exact Myers core is a narrow Apache-2.0 port from `similar 3.1.2`.
//! See `THIRD_PARTY.md` for the exact source mapping and modifications. This
//! module accepts only baseline-AI-safe and edited-AI bytes; it is not event,
//! anchor, approval, reconstruction, manifest, or persistence authority.
//! Original algorithm: Eugene W. Myers; see upstream references in `THIRD_PARTY.md`.
//! Modified by safeclone: the upstream recursive core is executed through a
//! bounded explicit stack, every deadline/resource exhaustion is an error,
//! and no upstream approximation or deadline fallback is retained.

use std::mem::size_of;
use std::time::{Duration, Instant};

pub(crate) const MAX_LOGICAL_LINES_PER_SIDE: usize = 65_536;
pub(crate) const MAX_REGIONS_PER_FILE: usize = 16_384;
pub(crate) const MAX_REGIONS_PER_REVIEW: usize = 100_000;
pub(crate) const MAX_WORKING_BYTES_PER_FILE: usize = 67_108_864;
pub(crate) const FILE_DEADLINE: Duration = Duration::from_millis(250);
pub(crate) const REVIEW_DEADLINE: Duration = Duration::from_secs(5);

// The review contract does not allocate a deterministic work limit. This is a
// conservative implementation guard, not a manifest or compatibility field.
const MAX_WORK_UNITS_PER_FILE: u64 = 16_777_216;
const MAX_DIFF_OPS: usize = MAX_LOGICAL_LINES_PER_SIDE * 2;
const MAX_WORK_STACK_ITEMS: usize = MAX_LOGICAL_LINES_PER_SIDE * 4 + 1;
const BYTE_COMPARISON_CHUNK: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiffError {
    DeadlineExceeded,
    WorkingMemoryExceeded,
    LineBoundExceeded,
    WorkBoundExceeded,
    RegionBoundExceeded,
    AggregateRegionBoundExceeded,
    InvalidScript,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DiffLimits {
    max_lines_per_side: usize,
    max_working_bytes: usize,
    max_work_units: u64,
    max_ops: usize,
    max_work_stack_items: usize,
    max_regions_per_file: usize,
}

impl DiffLimits {
    pub(crate) const fn accepted() -> Self {
        Self {
            max_lines_per_side: MAX_LOGICAL_LINES_PER_SIDE,
            max_working_bytes: MAX_WORKING_BYTES_PER_FILE,
            max_work_units: MAX_WORK_UNITS_PER_FILE,
            max_ops: MAX_DIFF_OPS,
            max_work_stack_items: MAX_WORK_STACK_ITEMS,
            max_regions_per_file: MAX_REGIONS_PER_FILE,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReportingFile<'a> {
    Absent,
    AiSafe(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LineRangeV1 {
    pub(crate) start_line: u32,
    pub(crate) end_line_exclusive: u32,
}

impl LineRangeV1 {
    fn from_zero_based(start: usize, end: usize) -> Result<Self, DiffError> {
        if start > end {
            return Err(DiffError::InvalidScript);
        }
        Ok(Self {
            start_line: u32::try_from(start.checked_add(1).ok_or(DiffError::InvalidScript)?)
                .map_err(|_| DiffError::InvalidScript)?,
            end_line_exclusive: u32::try_from(end.checked_add(1).ok_or(DiffError::InvalidScript)?)
                .map_err(|_| DiffError::InvalidScript)?,
        })
    }

    fn is_empty(self) -> bool {
        self.start_line == self.end_line_exclusive
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentChangeKindV1 {
    Insert,
    Delete,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContentChangeRegionV1 {
    pub(crate) kind: ContentChangeKindV1,
    pub(crate) before_range: LineRangeV1,
    pub(crate) after_range: LineRangeV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiffOp {
    Equal {
        before_index: u32,
        after_index: u32,
        len: u32,
    },
    Delete {
        before_index: u32,
        before_len: u32,
        after_index: u32,
    },
    Insert {
        before_index: u32,
        after_index: u32,
        after_len: u32,
    },
}

impl DiffOp {
    fn before_range(self) -> Result<(usize, usize), DiffError> {
        match self {
            Self::Equal {
                before_index, len, ..
            } => checked_range(before_index, len),
            Self::Delete {
                before_index,
                before_len,
                ..
            } => checked_range(before_index, before_len),
            Self::Insert { before_index, .. } => {
                let index = usize::try_from(before_index).map_err(|_| DiffError::InvalidScript)?;
                Ok((index, index))
            }
        }
    }

    fn after_range(self) -> Result<(usize, usize), DiffError> {
        match self {
            Self::Equal {
                after_index, len, ..
            } => checked_range(after_index, len),
            Self::Delete { after_index, .. } => {
                let index = usize::try_from(after_index).map_err(|_| DiffError::InvalidScript)?;
                Ok((index, index))
            }
            Self::Insert {
                after_index,
                after_len,
                ..
            } => checked_range(after_index, after_len),
        }
    }
}

fn checked_range(index: u32, len: u32) -> Result<(usize, usize), DiffError> {
    let start = usize::try_from(index).map_err(|_| DiffError::InvalidScript)?;
    let length = usize::try_from(len).map_err(|_| DiffError::InvalidScript)?;
    let end = start.checked_add(length).ok_or(DiffError::InvalidScript)?;
    Ok((start, end))
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ExactDiffScript {
    ops: Vec<DiffOp>,
    before_line_count: usize,
    after_line_count: usize,
}

impl ExactDiffScript {
    #[cfg(test)]
    fn edit_distance(&self) -> usize {
        self.ops
            .iter()
            .map(|op| match *op {
                DiffOp::Equal { .. } => 0,
                DiffOp::Delete { before_len, .. } => before_len as usize,
                DiffOp::Insert { after_len, .. } => after_len as usize,
            })
            .sum()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LineSpan {
    start: u32,
    end: u32,
}

struct LineTable<'a> {
    bytes: &'a [u8],
    spans: Vec<LineSpan>,
}

impl<'a> LineTable<'a> {
    fn len(&self) -> usize {
        self.spans.len()
    }

    fn line(&self, index: usize) -> Result<&'a [u8], DiffError> {
        let span = self.spans.get(index).ok_or(DiffError::InvalidScript)?;
        let start = usize::try_from(span.start).map_err(|_| DiffError::InvalidScript)?;
        let end = usize::try_from(span.end).map_err(|_| DiffError::InvalidScript)?;
        self.bytes.get(start..end).ok_or(DiffError::InvalidScript)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeadlineCheckpoint {
    Entry,
    LineScan,
    Prefix,
    Suffix,
    MiddleSnake,
    DivideStep,
    WorkStack,
    Replay,
    Projection,
    ReviewFile,
    Finish,
}

trait DeadlineSource {
    type Mark: Copy + Ord;

    fn now(&mut self, checkpoint: DeadlineCheckpoint) -> Self::Mark;
}

struct InstantDeadlineSource;

impl DeadlineSource for InstantDeadlineSource {
    type Mark = Instant;

    fn now(&mut self, _checkpoint: DeadlineCheckpoint) -> Self::Mark {
        Instant::now()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Deadlines<M> {
    file: M,
    aggregate: M,
}

impl<M: Copy + Ord> Deadlines<M> {
    fn exceeded(self, now: M) -> bool {
        now >= self.file || now >= self.aggregate
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DiffDeadlines(Deadlines<Instant>);

struct WorkGuard<'a, C: DeadlineSource> {
    source: &'a mut C,
    deadlines: Deadlines<C::Mark>,
    work: u64,
    max_work: u64,
}

impl<'a, C: DeadlineSource> WorkGuard<'a, C> {
    fn new(
        source: &'a mut C,
        deadlines: Deadlines<C::Mark>,
        max_work: u64,
    ) -> Result<Self, DiffError> {
        let mut value = Self {
            source,
            deadlines,
            work: 0,
            max_work,
        };
        value.deadline_only(DeadlineCheckpoint::Entry)?;
        Ok(value)
    }

    fn checkpoint(&mut self, checkpoint: DeadlineCheckpoint) -> Result<(), DiffError> {
        self.deadline_only(checkpoint)?;
        self.work = self
            .work
            .checked_add(1)
            .ok_or(DiffError::WorkBoundExceeded)?;
        if self.work > self.max_work {
            return Err(DiffError::WorkBoundExceeded);
        }
        Ok(())
    }

    fn deadline_only(&mut self, checkpoint: DeadlineCheckpoint) -> Result<(), DiffError> {
        let now = self.source.now(checkpoint);
        if self.deadlines.exceeded(now) {
            Err(DiffError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SolveRange {
    before_start: usize,
    before_end: usize,
    after_start: usize,
    after_end: usize,
}

impl SolveRange {
    fn before_len(self) -> usize {
        self.before_end - self.before_start
    }

    fn after_len(self) -> usize {
        self.after_end - self.after_start
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkItem {
    Solve(SolveRange),
    Equal {
        before_index: usize,
        after_index: usize,
        len: usize,
    },
}

struct Frontier {
    offset: isize,
    values: Vec<usize>,
}

impl Frontier {
    fn with_len(max_d: usize) -> Result<Self, DiffError> {
        let length = max_d
            .checked_mul(2)
            .ok_or(DiffError::WorkingMemoryExceeded)?;
        let mut values = Vec::new();
        reserve_exact(&mut values, length)?;
        values.resize(length, 0);
        Ok(Self {
            offset: isize::try_from(max_d).map_err(|_| DiffError::InvalidScript)?,
            values,
        })
    }

    fn get(&self, diagonal: isize) -> Result<usize, DiffError> {
        let index = diagonal
            .checked_add(self.offset)
            .ok_or(DiffError::InvalidScript)?;
        let index = usize::try_from(index).map_err(|_| DiffError::InvalidScript)?;
        self.values
            .get(index)
            .copied()
            .ok_or(DiffError::InvalidScript)
    }

    fn set(&mut self, diagonal: isize, value: usize) -> Result<(), DiffError> {
        let index = diagonal
            .checked_add(self.offset)
            .ok_or(DiffError::InvalidScript)?;
        let index = usize::try_from(index).map_err(|_| DiffError::InvalidScript)?;
        *self.values.get_mut(index).ok_or(DiffError::InvalidScript)? = value;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DiffMemoryLedger {
    pub(crate) before_line_spans: usize,
    pub(crate) after_line_spans: usize,
    pub(crate) before_line_ranks: usize,
    pub(crate) after_line_ranks: usize,
    pub(crate) forward_frontier: usize,
    pub(crate) reverse_frontier: usize,
    pub(crate) work_stack: usize,
    pub(crate) diff_ops: usize,
    pub(crate) replay_scratch: usize,
    pub(crate) region_projection_scratch: usize,
    pub(crate) vector_headers: usize,
    pub(crate) total: usize,
}

#[derive(Clone, Copy)]
struct ReplayCursor {
    before: usize,
    after: usize,
}

fn checked_bytes(count: usize, element_size: usize) -> Result<usize, DiffError> {
    count
        .checked_mul(element_size)
        .ok_or(DiffError::WorkingMemoryExceeded)
}

fn add_ledger(total: &mut usize, value: usize) -> Result<(), DiffError> {
    *total = total
        .checked_add(value)
        .ok_or(DiffError::WorkingMemoryExceeded)?;
    Ok(())
}

fn max_d(before_len: usize, after_len: usize) -> Result<usize, DiffError> {
    let total = before_len
        .checked_add(after_len)
        .ok_or(DiffError::WorkingMemoryExceeded)?;
    total
        .div_ceil(2)
        .checked_add(1)
        .ok_or(DiffError::WorkingMemoryExceeded)
}

fn memory_ledger(
    before_lines: usize,
    after_lines: usize,
    use_myers: bool,
    limits: DiffLimits,
) -> Result<DiffMemoryLedger, DiffError> {
    let before_line_spans = checked_bytes(before_lines, size_of::<LineSpan>())?;
    let after_line_spans = checked_bytes(after_lines, size_of::<LineSpan>())?;
    // The port compares borrowed byte slices exactly and therefore allocates no
    // hash/rank arrays. These explicit zero rows prevent an untracked rank
    // cache from being added later.
    let before_line_ranks = 0;
    let after_line_ranks = 0;

    let frontier_items = if use_myers {
        max_d(before_lines, after_lines)?
            .checked_mul(2)
            .ok_or(DiffError::WorkingMemoryExceeded)?
    } else {
        0
    };
    let forward_frontier = checked_bytes(frontier_items, size_of::<usize>())?;
    let reverse_frontier = checked_bytes(frontier_items, size_of::<usize>())?;
    let sequence_lines = before_lines
        .checked_add(after_lines)
        .ok_or(DiffError::WorkingMemoryExceeded)?;
    let work_stack_items = sequence_lines
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(DiffError::WorkingMemoryExceeded)?
        .min(limits.max_work_stack_items);
    let diff_op_items = sequence_lines.min(limits.max_ops);
    let work_stack = checked_bytes(work_stack_items, size_of::<WorkItem>())?;
    let diff_ops = checked_bytes(diff_op_items, size_of::<DiffOp>())?;
    let replay_scratch = size_of::<ReplayCursor>();
    let region_projection_scratch = checked_bytes(
        limits.max_regions_per_file,
        size_of::<ContentChangeRegionV1>(),
    )?;
    let vector_headers = checked_bytes(7, size_of::<Vec<usize>>())?;

    let mut total = 0;
    for value in [
        before_line_spans,
        after_line_spans,
        before_line_ranks,
        after_line_ranks,
        forward_frontier,
        reverse_frontier,
        work_stack,
        diff_ops,
        replay_scratch,
        region_projection_scratch,
        vector_headers,
    ] {
        add_ledger(&mut total, value)?;
    }

    Ok(DiffMemoryLedger {
        before_line_spans,
        after_line_spans,
        before_line_ranks,
        after_line_ranks,
        forward_frontier,
        reverse_frontier,
        work_stack,
        diff_ops,
        replay_scratch,
        region_projection_scratch,
        vector_headers,
        total,
    })
}

fn reserve_exact<T>(values: &mut Vec<T>, count: usize) -> Result<(), DiffError> {
    values
        .try_reserve_exact(count)
        .map_err(|_| DiffError::WorkingMemoryExceeded)?;
    // All production callers pass a fresh, non-ZST vector. Refuse an
    // allocator-reported capacity larger than the capacity charged by the
    // preflight ledger instead of retaining unaccounted working storage.
    if size_of::<T>() == 0 || values.capacity() != count {
        return Err(DiffError::WorkingMemoryExceeded);
    }
    Ok(())
}

fn count_lines<C: DeadlineSource>(
    bytes: &[u8],
    limits: DiffLimits,
    guard: &mut WorkGuard<'_, C>,
) -> Result<usize, DiffError> {
    if bytes.is_empty() {
        guard.checkpoint(DeadlineCheckpoint::LineScan)?;
        return Ok(1);
    }

    let mut newline_count = 0usize;
    for chunk in bytes.chunks(BYTE_COMPARISON_CHUNK) {
        guard.checkpoint(DeadlineCheckpoint::LineScan)?;
        newline_count = newline_count
            .checked_add(chunk.iter().filter(|byte| **byte == b'\n').count())
            .ok_or(DiffError::LineBoundExceeded)?;
        if newline_count > limits.max_lines_per_side {
            return Err(DiffError::LineBoundExceeded);
        }
    }
    let count = if bytes.last() == Some(&b'\n') {
        newline_count
    } else {
        newline_count
            .checked_add(1)
            .ok_or(DiffError::LineBoundExceeded)?
    };
    if count > limits.max_lines_per_side {
        Err(DiffError::LineBoundExceeded)
    } else {
        Ok(count)
    }
}

fn build_line_table<'a, C: DeadlineSource>(
    bytes: &'a [u8],
    line_count: usize,
    guard: &mut WorkGuard<'_, C>,
) -> Result<LineTable<'a>, DiffError> {
    let mut spans = Vec::new();
    reserve_exact(&mut spans, line_count)?;
    if bytes.is_empty() {
        spans.push(LineSpan { start: 0, end: 0 });
        return Ok(LineTable { bytes, spans });
    }

    let mut start = 0usize;
    for (chunk_index, chunk) in bytes.chunks(BYTE_COMPARISON_CHUNK).enumerate() {
        guard.checkpoint(DeadlineCheckpoint::LineScan)?;
        let chunk_start = chunk_index
            .checked_mul(BYTE_COMPARISON_CHUNK)
            .ok_or(DiffError::InvalidScript)?;
        for (offset, byte) in chunk.iter().enumerate() {
            if *byte == b'\n' {
                let end = chunk_start
                    .checked_add(offset)
                    .and_then(|value| value.checked_add(1))
                    .ok_or(DiffError::InvalidScript)?;
                spans.push(LineSpan {
                    start: u32::try_from(start).map_err(|_| DiffError::LineBoundExceeded)?,
                    end: u32::try_from(end).map_err(|_| DiffError::LineBoundExceeded)?,
                });
                start = end;
            }
        }
    }
    if start < bytes.len() {
        spans.push(LineSpan {
            start: u32::try_from(start).map_err(|_| DiffError::LineBoundExceeded)?,
            end: u32::try_from(bytes.len()).map_err(|_| DiffError::LineBoundExceeded)?,
        });
    }
    if spans.len() != line_count {
        return Err(DiffError::InvalidScript);
    }
    Ok(LineTable { bytes, spans })
}

fn slices_equal<C: DeadlineSource>(
    left: &[u8],
    right: &[u8],
    checkpoint: DeadlineCheckpoint,
    guard: &mut WorkGuard<'_, C>,
) -> Result<bool, DiffError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left_chunk, right_chunk) in left
        .chunks(BYTE_COMPARISON_CHUNK)
        .zip(right.chunks(BYTE_COMPARISON_CHUNK))
    {
        guard.checkpoint(checkpoint)?;
        if left_chunk != right_chunk {
            return Ok(false);
        }
    }
    if left.is_empty() {
        guard.checkpoint(checkpoint)?;
    }
    Ok(true)
}

fn lines_equal<C: DeadlineSource>(
    before: &LineTable<'_>,
    before_index: usize,
    after: &LineTable<'_>,
    after_index: usize,
    checkpoint: DeadlineCheckpoint,
    guard: &mut WorkGuard<'_, C>,
) -> Result<bool, DiffError> {
    slices_equal(
        before.line(before_index)?,
        after.line(after_index)?,
        checkpoint,
        guard,
    )
}

struct OpEmitter {
    ops: Vec<DiffOp>,
    max_ops: usize,
}

impl OpEmitter {
    fn new(capacity: usize, max_ops: usize) -> Result<Self, DiffError> {
        let mut ops = Vec::new();
        reserve_exact(&mut ops, capacity.min(max_ops))?;
        Ok(Self { ops, max_ops })
    }

    fn push(&mut self, op: DiffOp) -> Result<(), DiffError> {
        let nonempty = match op {
            DiffOp::Equal { len, .. } => len != 0,
            DiffOp::Delete { before_len, .. } => before_len != 0,
            DiffOp::Insert { after_len, .. } => after_len != 0,
        };
        if !nonempty {
            return Err(DiffError::InvalidScript);
        }

        if let Some(last) = self.ops.last_mut() {
            match (last, op) {
                (
                    DiffOp::Equal {
                        before_index,
                        after_index,
                        len,
                    },
                    DiffOp::Equal {
                        before_index: next_before,
                        after_index: next_after,
                        len: next_len,
                    },
                ) if before_index.checked_add(*len) == Some(next_before)
                    && after_index.checked_add(*len) == Some(next_after) =>
                {
                    *len = len
                        .checked_add(next_len)
                        .ok_or(DiffError::WorkBoundExceeded)?;
                    return Ok(());
                }
                (
                    DiffOp::Delete {
                        before_index,
                        before_len,
                        after_index,
                    },
                    DiffOp::Delete {
                        before_index: next_before,
                        before_len: next_len,
                        after_index: next_after,
                    },
                ) if before_index.checked_add(*before_len) == Some(next_before)
                    && *after_index == next_after =>
                {
                    *before_len = before_len
                        .checked_add(next_len)
                        .ok_or(DiffError::WorkBoundExceeded)?;
                    return Ok(());
                }
                (
                    DiffOp::Insert {
                        before_index,
                        after_index,
                        after_len,
                    },
                    DiffOp::Insert {
                        before_index: next_before,
                        after_index: next_after,
                        after_len: next_len,
                    },
                ) if *before_index == next_before
                    && after_index.checked_add(*after_len) == Some(next_after) =>
                {
                    *after_len = after_len
                        .checked_add(next_len)
                        .ok_or(DiffError::WorkBoundExceeded)?;
                    return Ok(());
                }
                _ => {}
            }
        }

        if self.ops.len() >= self.max_ops {
            return Err(DiffError::WorkBoundExceeded);
        }
        self.ops.push(op);
        Ok(())
    }

    fn equal(&mut self, before: usize, after: usize, len: usize) -> Result<(), DiffError> {
        self.push(DiffOp::Equal {
            before_index: u32::try_from(before).map_err(|_| DiffError::InvalidScript)?,
            after_index: u32::try_from(after).map_err(|_| DiffError::InvalidScript)?,
            len: u32::try_from(len).map_err(|_| DiffError::InvalidScript)?,
        })
    }

    fn delete(&mut self, before: usize, len: usize, after: usize) -> Result<(), DiffError> {
        self.push(DiffOp::Delete {
            before_index: u32::try_from(before).map_err(|_| DiffError::InvalidScript)?,
            before_len: u32::try_from(len).map_err(|_| DiffError::InvalidScript)?,
            after_index: u32::try_from(after).map_err(|_| DiffError::InvalidScript)?,
        })
    }

    fn insert(&mut self, before: usize, after: usize, len: usize) -> Result<(), DiffError> {
        self.push(DiffOp::Insert {
            before_index: u32::try_from(before).map_err(|_| DiffError::InvalidScript)?,
            after_index: u32::try_from(after).map_err(|_| DiffError::InvalidScript)?,
            after_len: u32::try_from(len).map_err(|_| DiffError::InvalidScript)?,
        })
    }
}

fn common_prefix<C: DeadlineSource>(
    before: &LineTable<'_>,
    after: &LineTable<'_>,
    range: SolveRange,
    guard: &mut WorkGuard<'_, C>,
) -> Result<usize, DiffError> {
    let maximum = range.before_len().min(range.after_len());
    let mut matched = 0usize;
    while matched < maximum
        && lines_equal(
            before,
            range.before_start + matched,
            after,
            range.after_start + matched,
            DeadlineCheckpoint::Prefix,
            guard,
        )?
    {
        matched += 1;
    }
    Ok(matched)
}

fn common_suffix<C: DeadlineSource>(
    before: &LineTable<'_>,
    after: &LineTable<'_>,
    range: SolveRange,
    guard: &mut WorkGuard<'_, C>,
) -> Result<usize, DiffError> {
    let maximum = range.before_len().min(range.after_len());
    let mut matched = 0usize;
    while matched < maximum
        && lines_equal(
            before,
            range.before_end - 1 - matched,
            after,
            range.after_end - 1 - matched,
            DeadlineCheckpoint::Suffix,
            guard,
        )?
    {
        matched += 1;
    }
    Ok(matched)
}

fn find_middle_snake<C: DeadlineSource>(
    before: &LineTable<'_>,
    after: &LineTable<'_>,
    range: SolveRange,
    forward: &mut Frontier,
    reverse: &mut Frontier,
    guard: &mut WorkGuard<'_, C>,
) -> Result<(usize, usize), DiffError> {
    let before_len = range.before_len();
    let after_len = range.after_len();
    let delta = isize::try_from(before_len)
        .and_then(|left| isize::try_from(after_len).map(|right| left - right))
        .map_err(|_| DiffError::InvalidScript)?;
    let odd = delta & 1 == 1;

    forward.set(1, 0)?;
    reverse.set(1, 0)?;
    let d_max = max_d(before_len, after_len)?;

    for d_usize in 0..d_max {
        guard.checkpoint(DeadlineCheckpoint::MiddleSnake)?;
        let d = isize::try_from(d_usize).map_err(|_| DiffError::InvalidScript)?;

        for k in (-d..=d).rev().step_by(2) {
            guard.checkpoint(DeadlineCheckpoint::MiddleSnake)?;
            let mut x = if k == -d || (k != d && forward.get(k - 1)? < forward.get(k + 1)?) {
                forward.get(k + 1)?
            } else {
                forward
                    .get(k - 1)?
                    .checked_add(1)
                    .ok_or(DiffError::InvalidScript)?
            };
            let y_signed = isize::try_from(x)
                .map_err(|_| DiffError::InvalidScript)?
                .checked_sub(k)
                .ok_or(DiffError::InvalidScript)?;
            // Myers deliberately visits diagonals just outside the edit graph.
            // Upstream's signed-to-unsigned cast makes a negative y an
            // out-of-range sentinel; retain that control flow explicitly
            // without relying on wrapping conversion.
            let mut y = usize::try_from(y_signed).unwrap_or(usize::MAX);
            let (x_start, y_start) = (x, y);
            while x < before_len
                && y < after_len
                && lines_equal(
                    before,
                    range.before_start + x,
                    after,
                    range.after_start + y,
                    DeadlineCheckpoint::MiddleSnake,
                    guard,
                )?
            {
                x += 1;
                y += 1;
            }
            forward.set(k, x)?;

            let reciprocal = k.checked_sub(delta).ok_or(DiffError::InvalidScript)?;
            if odd && d > 0 && reciprocal.abs() < d {
                let reverse_diagonal = reciprocal.checked_neg().ok_or(DiffError::InvalidScript)?;
                if forward
                    .get(k)?
                    .checked_add(reverse.get(reverse_diagonal)?)
                    .ok_or(DiffError::InvalidScript)?
                    >= before_len
                {
                    if x_start > before_len || y_start > after_len {
                        return Err(DiffError::InvalidScript);
                    }
                    return Ok((
                        range
                            .before_start
                            .checked_add(x_start)
                            .ok_or(DiffError::InvalidScript)?,
                        range
                            .after_start
                            .checked_add(y_start)
                            .ok_or(DiffError::InvalidScript)?,
                    ));
                }
            }
        }

        for k in (-d..=d).rev().step_by(2) {
            guard.checkpoint(DeadlineCheckpoint::MiddleSnake)?;
            let mut x = if k == -d || (k != d && reverse.get(k - 1)? < reverse.get(k + 1)?) {
                reverse.get(k + 1)?
            } else {
                reverse
                    .get(k - 1)?
                    .checked_add(1)
                    .ok_or(DiffError::InvalidScript)?
            };
            let y_signed = isize::try_from(x)
                .map_err(|_| DiffError::InvalidScript)?
                .checked_sub(k)
                .ok_or(DiffError::InvalidScript)?;
            let mut y = usize::try_from(y_signed).unwrap_or(usize::MAX);
            while x < before_len
                && y < after_len
                && lines_equal(
                    before,
                    range.before_end - 1 - x,
                    after,
                    range.after_end - 1 - y,
                    DeadlineCheckpoint::MiddleSnake,
                    guard,
                )?
            {
                x += 1;
                y += 1;
            }
            reverse.set(k, x)?;

            let reciprocal = k.checked_sub(delta).ok_or(DiffError::InvalidScript)?;
            if !odd && reciprocal.abs() <= d {
                let forward_diagonal = reciprocal.checked_neg().ok_or(DiffError::InvalidScript)?;
                if reverse
                    .get(k)?
                    .checked_add(forward.get(forward_diagonal)?)
                    .ok_or(DiffError::InvalidScript)?
                    >= before_len
                {
                    let before_offset =
                        before_len.checked_sub(x).ok_or(DiffError::InvalidScript)?;
                    let after_offset = after_len.checked_sub(y).ok_or(DiffError::InvalidScript)?;
                    return Ok((
                        range
                            .before_start
                            .checked_add(before_offset)
                            .ok_or(DiffError::InvalidScript)?,
                        range
                            .after_start
                            .checked_add(after_offset)
                            .ok_or(DiffError::InvalidScript)?,
                    ));
                }
            }
        }
    }

    Err(DiffError::InvalidScript)
}

fn push_work(
    stack: &mut Vec<WorkItem>,
    value: WorkItem,
    limits: DiffLimits,
) -> Result<(), DiffError> {
    if stack.len() >= limits.max_work_stack_items {
        return Err(DiffError::WorkBoundExceeded);
    }
    stack.push(value);
    Ok(())
}

fn myers_ops<C: DeadlineSource>(
    before: &LineTable<'_>,
    after: &LineTable<'_>,
    limits: DiffLimits,
    guard: &mut WorkGuard<'_, C>,
) -> Result<Vec<DiffOp>, DiffError> {
    let maximum_d = max_d(before.len(), after.len())?;
    let mut forward = Frontier::with_len(maximum_d)?;
    let mut reverse = Frontier::with_len(maximum_d)?;
    let mut stack = Vec::new();
    let sequence_lines = before
        .len()
        .checked_add(after.len())
        .ok_or(DiffError::WorkingMemoryExceeded)?;
    let stack_capacity = sequence_lines
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(DiffError::WorkingMemoryExceeded)?
        .min(limits.max_work_stack_items);
    reserve_exact(&mut stack, stack_capacity)?;
    let mut emitter = OpEmitter::new(sequence_lines, limits.max_ops)?;
    push_work(
        &mut stack,
        WorkItem::Solve(SolveRange {
            before_start: 0,
            before_end: before.len(),
            after_start: 0,
            after_end: after.len(),
        }),
        limits,
    )?;

    while let Some(item) = stack.pop() {
        guard.checkpoint(DeadlineCheckpoint::WorkStack)?;
        match item {
            WorkItem::Equal {
                before_index,
                after_index,
                len,
            } => emitter.equal(before_index, after_index, len)?,
            WorkItem::Solve(mut range) => {
                let prefix = common_prefix(before, after, range, guard)?;
                if prefix != 0 {
                    emitter.equal(range.before_start, range.after_start, prefix)?;
                    range.before_start += prefix;
                    range.after_start += prefix;
                }

                let suffix = common_suffix(before, after, range, guard)?;
                let suffix_before = range.before_end - suffix;
                let suffix_after = range.after_end - suffix;
                range.before_end -= suffix;
                range.after_end -= suffix;
                if suffix != 0 {
                    push_work(
                        &mut stack,
                        WorkItem::Equal {
                            before_index: suffix_before,
                            after_index: suffix_after,
                            len: suffix,
                        },
                        limits,
                    )?;
                }

                match (range.before_len(), range.after_len()) {
                    (0, 0) => {}
                    (before_len, 0) => {
                        emitter.delete(range.before_start, before_len, range.after_start)?;
                    }
                    (0, after_len) => {
                        emitter.insert(range.before_start, range.after_start, after_len)?;
                    }
                    _ => {
                        let (before_split, after_split) = find_middle_snake(
                            before,
                            after,
                            range,
                            &mut forward,
                            &mut reverse,
                            guard,
                        )?;
                        guard.checkpoint(DeadlineCheckpoint::DivideStep)?;
                        if before_split < range.before_start
                            || before_split > range.before_end
                            || after_split < range.after_start
                            || after_split > range.after_end
                            || (before_split == range.before_start
                                && after_split == range.after_start)
                            || (before_split == range.before_end && after_split == range.after_end)
                        {
                            return Err(DiffError::InvalidScript);
                        }
                        push_work(
                            &mut stack,
                            WorkItem::Solve(SolveRange {
                                before_start: before_split,
                                before_end: range.before_end,
                                after_start: after_split,
                                after_end: range.after_end,
                            }),
                            limits,
                        )?;
                        push_work(
                            &mut stack,
                            WorkItem::Solve(SolveRange {
                                before_start: range.before_start,
                                before_end: before_split,
                                after_start: range.after_start,
                                after_end: after_split,
                            }),
                            limits,
                        )?;
                    }
                }
            }
        }
    }

    Ok(emitter.ops)
}

fn verify_script<C: DeadlineSource>(
    before: &LineTable<'_>,
    after: &LineTable<'_>,
    ops: &[DiffOp],
    guard: &mut WorkGuard<'_, C>,
) -> Result<(), DiffError> {
    let mut cursor = ReplayCursor {
        before: 0,
        after: 0,
    };
    for op in ops {
        guard.checkpoint(DeadlineCheckpoint::Replay)?;
        let (before_start, before_end) = op.before_range()?;
        let (after_start, after_end) = op.after_range()?;
        if before_start != cursor.before || after_start != cursor.after {
            return Err(DiffError::InvalidScript);
        }
        match *op {
            DiffOp::Equal { .. } => {
                let before_len = before_end - before_start;
                let after_len = after_end - after_start;
                if before_len == 0 || before_len != after_len {
                    return Err(DiffError::InvalidScript);
                }
                for offset in 0..before_len {
                    if !lines_equal(
                        before,
                        before_start + offset,
                        after,
                        after_start + offset,
                        DeadlineCheckpoint::Replay,
                        guard,
                    )? {
                        return Err(DiffError::InvalidScript);
                    }
                }
            }
            DiffOp::Delete { .. } => {
                if before_start == before_end || after_start != after_end {
                    return Err(DiffError::InvalidScript);
                }
            }
            DiffOp::Insert { .. } => {
                if before_start != before_end || after_start == after_end {
                    return Err(DiffError::InvalidScript);
                }
            }
        }
        if before_end > before.len() || after_end > after.len() {
            return Err(DiffError::InvalidScript);
        }
        cursor.before = before_end;
        cursor.after = after_end;
    }
    if cursor.before != before.len() || cursor.after != after.len() {
        return Err(DiffError::InvalidScript);
    }
    guard.deadline_only(DeadlineCheckpoint::Finish)
}

fn make_fast_path_ops(
    before_lines: usize,
    after_lines: usize,
    before_present: bool,
    after_present: bool,
    exact_equal: bool,
    limits: DiffLimits,
) -> Result<Option<Vec<DiffOp>>, DiffError> {
    let mut emitter = OpEmitter::new(1, limits.max_ops)?;
    if !before_present && !after_present {
        return Err(DiffError::InvalidScript);
    }
    if !before_present {
        emitter.insert(0, 0, after_lines)?;
        return Ok(Some(emitter.ops));
    }
    if !after_present {
        emitter.delete(0, before_lines, 0)?;
        return Ok(Some(emitter.ops));
    }
    if exact_equal {
        emitter.equal(0, 0, before_lines)?;
        return Ok(Some(emitter.ops));
    }
    Ok(None)
}

fn build_exact_script<C: DeadlineSource>(
    before_input: ReportingFile<'_>,
    after_input: ReportingFile<'_>,
    limits: DiffLimits,
    guard: &mut WorkGuard<'_, C>,
) -> Result<ExactDiffScript, DiffError> {
    let (before_present, before_bytes) = match before_input {
        ReportingFile::Absent => (false, &[][..]),
        ReportingFile::AiSafe(bytes) => (true, bytes),
    };
    let (after_present, after_bytes) = match after_input {
        ReportingFile::Absent => (false, &[][..]),
        ReportingFile::AiSafe(bytes) => (true, bytes),
    };
    if !before_present && !after_present {
        return Err(DiffError::InvalidScript);
    }

    let before_line_count = if before_present {
        count_lines(before_bytes, limits, guard)?
    } else {
        0
    };
    let after_line_count = if after_present {
        count_lines(after_bytes, limits, guard)?
    } else {
        0
    };
    let use_myers = before_present && after_present;
    let ledger = memory_ledger(before_line_count, after_line_count, use_myers, limits)?;
    if ledger.total > limits.max_working_bytes {
        return Err(DiffError::WorkingMemoryExceeded);
    }

    let before = if before_present {
        build_line_table(before_bytes, before_line_count, guard)?
    } else {
        LineTable {
            bytes: &[],
            spans: Vec::new(),
        }
    };
    let after = if after_present {
        build_line_table(after_bytes, after_line_count, guard)?
    } else {
        LineTable {
            bytes: &[],
            spans: Vec::new(),
        }
    };
    let exact_equal = before_present
        && after_present
        && slices_equal(before_bytes, after_bytes, DeadlineCheckpoint::Prefix, guard)?;

    let ops = match make_fast_path_ops(
        before.len(),
        after.len(),
        before_present,
        after_present,
        exact_equal,
        limits,
    )? {
        Some(ops) => ops,
        None => myers_ops(&before, &after, limits, guard)?,
    };
    verify_script(&before, &after, &ops, guard)?;
    Ok(ExactDiffScript {
        ops,
        before_line_count: before.len(),
        after_line_count: after.len(),
    })
}

// Retained as the narrow exact-diff exact-script API even though review production
// consumes the stricter combined script-and-region path below.
#[allow(dead_code)]
fn build_exact_script_with_source<C: DeadlineSource>(
    before: ReportingFile<'_>,
    after: ReportingFile<'_>,
    limits: DiffLimits,
    deadlines: Deadlines<C::Mark>,
    source: &mut C,
) -> Result<ExactDiffScript, DiffError> {
    let mut guard = WorkGuard::new(source, deadlines, limits.max_work_units)?;
    build_exact_script(before, after, limits, &mut guard)
}

fn flush_region(
    regions: &mut Vec<ContentChangeRegionV1>,
    pending: &mut Option<(usize, usize, usize, usize)>,
    limit: usize,
) -> Result<(), DiffError> {
    let Some((before_start, before_end, after_start, after_end)) = pending.take() else {
        return Ok(());
    };
    if regions.len() >= limit {
        return Err(DiffError::RegionBoundExceeded);
    }
    let before_range = LineRangeV1::from_zero_based(before_start, before_end)?;
    let after_range = LineRangeV1::from_zero_based(after_start, after_end)?;
    let kind = match (before_range.is_empty(), after_range.is_empty()) {
        (true, false) => ContentChangeKindV1::Insert,
        (false, true) => ContentChangeKindV1::Delete,
        (false, false) => ContentChangeKindV1::Replace,
        (true, true) => return Err(DiffError::InvalidScript),
    };
    regions.push(ContentChangeRegionV1 {
        kind,
        before_range,
        after_range,
    });
    Ok(())
}

fn project_regions<C: DeadlineSource>(
    script: &ExactDiffScript,
    limits: DiffLimits,
    guard: &mut WorkGuard<'_, C>,
) -> Result<Vec<ContentChangeRegionV1>, DiffError> {
    let mut regions = Vec::new();
    reserve_exact(
        &mut regions,
        script.ops.len().min(limits.max_regions_per_file),
    )?;
    let mut before_cursor = 0usize;
    let mut after_cursor = 0usize;
    let mut pending = None;

    for op in &script.ops {
        guard.checkpoint(DeadlineCheckpoint::Projection)?;
        let (before_start, before_end) = op.before_range()?;
        let (after_start, after_end) = op.after_range()?;
        if before_start != before_cursor || after_start != after_cursor {
            return Err(DiffError::InvalidScript);
        }
        match *op {
            DiffOp::Equal { .. } => {
                flush_region(&mut regions, &mut pending, limits.max_regions_per_file)?;
            }
            DiffOp::Delete { .. } | DiffOp::Insert { .. } => {
                let value = pending.get_or_insert((
                    before_cursor,
                    before_cursor,
                    after_cursor,
                    after_cursor,
                ));
                value.1 = before_end;
                value.3 = after_end;
            }
        }
        before_cursor = before_end;
        after_cursor = after_end;
    }
    flush_region(&mut regions, &mut pending, limits.max_regions_per_file)?;
    if before_cursor != script.before_line_count || after_cursor != script.after_line_count {
        return Err(DiffError::InvalidScript);
    }
    guard.deadline_only(DeadlineCheckpoint::Finish)?;
    Ok(regions)
}

fn diff_and_regions_with_source<C: DeadlineSource>(
    before: ReportingFile<'_>,
    after: ReportingFile<'_>,
    limits: DiffLimits,
    deadlines: Deadlines<C::Mark>,
    source: &mut C,
) -> Result<(ExactDiffScript, Vec<ContentChangeRegionV1>), DiffError> {
    let mut guard = WorkGuard::new(source, deadlines, limits.max_work_units)?;
    let script = build_exact_script(before, after, limits, &mut guard)?;
    let regions = project_regions(&script, limits, &mut guard)?;
    Ok((script, regions))
}

pub(crate) struct StrictLineDiff;

impl StrictLineDiff {
    // Retained for focused exact-script verification and future reporting
    // consumers; current review manifest projection consumes `regions`.
    #[allow(dead_code)]
    pub(crate) fn diff(
        before: ReportingFile<'_>,
        after: ReportingFile<'_>,
        limits: DiffLimits,
        deadlines: DiffDeadlines,
    ) -> Result<ExactDiffScript, DiffError> {
        let mut source = InstantDeadlineSource;
        build_exact_script_with_source(before, after, limits, deadlines.0, &mut source)
    }

    pub(crate) fn regions(
        before: ReportingFile<'_>,
        after: ReportingFile<'_>,
        limits: DiffLimits,
        deadlines: DiffDeadlines,
    ) -> Result<Vec<ContentChangeRegionV1>, DiffError> {
        let mut source = InstantDeadlineSource;
        let (_, regions) =
            diff_and_regions_with_source(before, after, limits, deadlines.0, &mut source)?;
        Ok(regions)
    }
}

pub(crate) struct ReviewDiffBudget {
    aggregate_deadline: Instant,
    regions: usize,
}

#[cfg(test)]
std::thread_local! {
    static FORCE_REVIEW_START_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) struct ReviewStartFailureGuard;

#[cfg(test)]
impl Drop for ReviewStartFailureGuard {
    fn drop(&mut self) {
        FORCE_REVIEW_START_FAILURE.with(|value| value.set(false));
    }
}

#[cfg(test)]
pub(crate) fn install_review_start_failure() -> ReviewStartFailureGuard {
    FORCE_REVIEW_START_FAILURE.with(|value| {
        assert!(!value.replace(true), "nested review diff failure hook");
    });
    ReviewStartFailureGuard
}

fn select_file_deadlines<M: Copy + Ord>(
    now: M,
    per_file: M,
    aggregate: M,
) -> Result<Deadlines<M>, DiffError> {
    if now >= aggregate {
        return Err(DiffError::DeadlineExceeded);
    }
    Ok(Deadlines {
        file: per_file.min(aggregate),
        aggregate,
    })
}

impl ReviewDiffBudget {
    pub(crate) fn start() -> Result<Self, DiffError> {
        #[cfg(test)]
        if FORCE_REVIEW_START_FAILURE.with(std::cell::Cell::get) {
            return Err(DiffError::DeadlineExceeded);
        }
        let now = Instant::now();
        let aggregate_deadline = now
            .checked_add(REVIEW_DEADLINE)
            .ok_or(DiffError::DeadlineExceeded)?;
        Ok(Self {
            aggregate_deadline,
            regions: 0,
        })
    }

    pub(crate) fn begin_file(&self) -> Result<DiffDeadlines, DiffError> {
        let mut source = InstantDeadlineSource;
        let now = source.now(DeadlineCheckpoint::ReviewFile);
        let per_file = now
            .checked_add(FILE_DEADLINE)
            .ok_or(DiffError::DeadlineExceeded)?;
        select_file_deadlines(now, per_file, self.aggregate_deadline).map(DiffDeadlines)
    }

    pub(crate) fn accept_regions(&mut self, count: usize) -> Result<(), DiffError> {
        let next = self
            .regions
            .checked_add(count)
            .ok_or(DiffError::AggregateRegionBoundExceeded)?;
        if next > MAX_REGIONS_PER_REVIEW {
            return Err(DiffError::AggregateRegionBoundExceeded);
        }
        self.regions = next;
        Ok(())
    }

    #[cfg(test)]
    fn regions(&self) -> usize {
        self.regions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct Trigger {
        checkpoint: DeadlineCheckpoint,
        occurrence: usize,
        deadline: u64,
    }

    struct FakeClock {
        mark: u64,
        trigger: Option<Trigger>,
        matching_hits: usize,
    }

    impl FakeClock {
        fn fixed(mark: u64) -> Self {
            Self {
                mark,
                trigger: None,
                matching_hits: 0,
            }
        }

        fn expires_on(checkpoint: DeadlineCheckpoint, occurrence: usize) -> Self {
            Self {
                mark: 0,
                trigger: Some(Trigger {
                    checkpoint,
                    occurrence,
                    deadline: 10,
                }),
                matching_hits: 0,
            }
        }
    }

    impl DeadlineSource for FakeClock {
        type Mark = u64;

        fn now(&mut self, checkpoint: DeadlineCheckpoint) -> Self::Mark {
            if let Some(trigger) = self.trigger {
                if checkpoint == trigger.checkpoint {
                    self.matching_hits += 1;
                    if self.matching_hits >= trigger.occurrence {
                        self.mark = trigger.deadline;
                    }
                }
            }
            self.mark
        }
    }

    fn fake_deadlines() -> Deadlines<u64> {
        Deadlines {
            file: 10,
            aggregate: 20,
        }
    }

    fn run(
        before: ReportingFile<'_>,
        after: ReportingFile<'_>,
    ) -> Result<(ExactDiffScript, Vec<ContentChangeRegionV1>), DiffError> {
        let mut clock = FakeClock::fixed(0);
        diff_and_regions_with_source(
            before,
            after,
            DiffLimits::accepted(),
            fake_deadlines(),
            &mut clock,
        )
    }

    fn present_regions(
        before: &[u8],
        after: &[u8],
    ) -> Result<Vec<ContentChangeRegionV1>, DiffError> {
        run(ReportingFile::AiSafe(before), ReportingFile::AiSafe(after)).map(|(_, regions)| regions)
    }

    fn region(
        kind: ContentChangeKindV1,
        before_start: u32,
        before_end: u32,
        after_start: u32,
        after_end: u32,
    ) -> ContentChangeRegionV1 {
        ContentChangeRegionV1 {
            kind,
            before_range: LineRangeV1 {
                start_line: before_start,
                end_line_exclusive: before_end,
            },
            after_range: LineRangeV1 {
                start_line: after_start,
                end_line_exclusive: after_end,
            },
        }
    }

    fn line_table(bytes: &[u8]) -> LineTable<'_> {
        let mut clock = FakeClock::fixed(0);
        let mut guard = WorkGuard::new(&mut clock, fake_deadlines(), MAX_WORK_UNITS_PER_FILE)
            .expect("live fake deadline");
        let count = count_lines(bytes, DiffLimits::accepted(), &mut guard).expect("line count");
        build_line_table(bytes, count, &mut guard).expect("line table")
    }

    fn logical_lines(bytes: &[u8]) -> Vec<&[u8]> {
        let table = line_table(bytes);
        (0..table.len())
            .map(|index| table.line(index).expect("line"))
            .collect()
    }

    fn lcs_edit_distance(before: &[u8], after: &[u8]) -> usize {
        let before = logical_lines(before);
        let after = logical_lines(after);
        let width = after.len() + 1;
        let mut lengths = vec![0usize; (before.len() + 1) * width];
        for before_index in (0..before.len()).rev() {
            for after_index in (0..after.len()).rev() {
                let index = before_index * width + after_index;
                lengths[index] = if before[before_index] == after[after_index] {
                    lengths[(before_index + 1) * width + after_index + 1] + 1
                } else {
                    lengths[(before_index + 1) * width + after_index].max(lengths[index + 1])
                };
            }
        }
        before.len() + after.len() - 2 * lengths[0]
    }

    fn encode_sequence(mut value: usize, len: usize) -> Vec<u8> {
        let mut symbols = vec![0u8; len];
        for symbol in symbols.iter_mut().rev() {
            *symbol = (value % 3) as u8;
            value /= 3;
        }
        let mut bytes = Vec::with_capacity(len * 2);
        for symbol in symbols {
            bytes.push(b'A' + symbol);
            bytes.push(b'\n');
        }
        bytes
    }

    fn assert_region_order(regions: &[ContentChangeRegionV1]) {
        for pair in regions.windows(2) {
            assert!(pair[0].before_range.end_line_exclusive <= pair[1].before_range.start_line);
            assert!(pair[0].after_range.end_line_exclusive <= pair[1].after_range.start_line);
        }
    }

    #[test]
    fn logical_line_model_is_byte_exact() {
        let cases: &[(&[u8], &[&[u8]])] = &[
            (b"", &[b""]),
            (b"\n", &[b"\n"]),
            (b"a\n", &[b"a\n"]),
            (b"a\nb", &[b"a\n", b"b"]),
            (b"a\r\nb\n", &[b"a\r\n", b"b\n"]),
            (b"a\rb\n\r", &[b"a\rb\n", b"\r"]),
            (b"unterminated", &[b"unterminated"]),
        ];
        for (bytes, expected) in cases {
            assert_eq!(logical_lines(bytes), *expected);
        }
    }

    #[test]
    fn fast_paths_cover_empty_added_deleted_and_exact_move() {
        assert!(present_regions(b"", b"")
            .expect("empty unchanged")
            .is_empty());
        assert!(present_regions(b"same\n", b"same\n")
            .expect("exact unchanged")
            .is_empty());

        let (_, added) =
            run(ReportingFile::Absent, ReportingFile::AiSafe(b"one\ntwo")).expect("added file");
        assert_eq!(added, vec![region(ContentChangeKindV1::Insert, 1, 1, 1, 3)]);

        let (_, empty_added) =
            run(ReportingFile::Absent, ReportingFile::AiSafe(b"")).expect("empty added file");
        assert_eq!(
            empty_added,
            vec![region(ContentChangeKindV1::Insert, 1, 1, 1, 2)]
        );

        let (_, deleted) =
            run(ReportingFile::AiSafe(b"one\ntwo"), ReportingFile::Absent).expect("deleted file");
        assert_eq!(
            deleted,
            vec![region(ContentChangeKindV1::Delete, 1, 3, 1, 1)]
        );

        let (_, empty_deleted) =
            run(ReportingFile::AiSafe(b""), ReportingFile::Absent).expect("empty deleted file");
        assert_eq!(
            empty_deleted,
            vec![region(ContentChangeKindV1::Delete, 1, 2, 1, 1)]
        );

        assert_eq!(
            run(ReportingFile::Absent, ReportingFile::Absent),
            Err(DiffError::InvalidScript)
        );
    }

    #[test]
    fn canonical_regions_cover_insert_delete_replace_and_separation() {
        let cases = [
            (
                b"b\nc\n".as_slice(),
                b"a\nb\nc\n".as_slice(),
                vec![region(ContentChangeKindV1::Insert, 1, 1, 1, 2)],
            ),
            (
                b"a\nc\n".as_slice(),
                b"a\nb\nc\n".as_slice(),
                vec![region(ContentChangeKindV1::Insert, 2, 2, 2, 3)],
            ),
            (
                b"a\nb\n".as_slice(),
                b"a\nb\nc\n".as_slice(),
                vec![region(ContentChangeKindV1::Insert, 3, 3, 3, 4)],
            ),
            (
                b"a\nb\nc\n".as_slice(),
                b"b\nc\n".as_slice(),
                vec![region(ContentChangeKindV1::Delete, 1, 2, 1, 1)],
            ),
            (
                b"a\nb\nc\n".as_slice(),
                b"a\nc\n".as_slice(),
                vec![region(ContentChangeKindV1::Delete, 2, 3, 2, 2)],
            ),
            (
                b"a\nb\nc\n".as_slice(),
                b"a\nb\n".as_slice(),
                vec![region(ContentChangeKindV1::Delete, 3, 4, 3, 3)],
            ),
            (
                b"a\nold\nc\n".as_slice(),
                b"a\nnew\nc\n".as_slice(),
                vec![region(ContentChangeKindV1::Replace, 2, 3, 2, 3)],
            ),
            (
                b"old-a\nold-b\nkeep\n".as_slice(),
                b"new-a\nnew-b\nkeep\n".as_slice(),
                vec![region(ContentChangeKindV1::Replace, 1, 3, 1, 3)],
            ),
            (
                b"old-a\nkeep\nold-b\n".as_slice(),
                b"new-a\nkeep\nnew-b\n".as_slice(),
                vec![
                    region(ContentChangeKindV1::Replace, 1, 2, 1, 2),
                    region(ContentChangeKindV1::Replace, 3, 4, 3, 4),
                ],
            ),
        ];

        for (before, after, expected) in cases {
            let actual = present_regions(before, after).expect("exact region result");
            assert_eq!(actual, expected, "before={before:?} after={after:?}");
            assert_region_order(&actual);
        }
    }

    #[test]
    fn exact_replay_corpus_covers_repetition_reorder_and_newlines() {
        let large_prefix = [b"prefix\n".repeat(512), b"old\n".to_vec()].concat();
        let large_prefix_after = [b"prefix\n".repeat(512), b"new\n".to_vec()].concat();
        let large_suffix = [b"old\n".to_vec(), b"suffix\n".repeat(512)].concat();
        let large_suffix_after = [b"new\n".to_vec(), b"suffix\n".repeat(512)].concat();
        let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"a\na\na\n".to_vec(), b"a\na\na\n".to_vec()),
            (b"a\na\nb\na\n".to_vec(), b"a\nb\na\na\n".to_vec()),
            (b"a\nb\na\nb\n".to_vec(), b"b\na\nb\na\n".to_vec()),
            (b"a\nb\nc\n".to_vec(), b"c\nb\na\n".to_vec()),
            (b"a\nb\nc\n".to_vec(), b"x\ny\nz\n".to_vec()),
            (b"one\r\ntwo\r\n".to_vec(), b"one\ntwo\r\n".to_vec()),
            (b"one\ntwo\n".to_vec(), b"one\nTWO\n".to_vec()),
            (b"one\rtwo\nend".to_vec(), b"one\rtwo\nEND".to_vec()),
            (b"final\nline".to_vec(), b"final\nchanged".to_vec()),
            (large_prefix, large_prefix_after),
            (large_suffix, large_suffix_after),
        ];
        for (before, after) in cases {
            let (script, regions) = run(
                ReportingFile::AiSafe(&before),
                ReportingFile::AiSafe(&after),
            )
            .expect("exact corpus item");
            assert_eq!(script.edit_distance(), lcs_edit_distance(&before, &after));
            assert_region_order(&regions);
        }
    }

    #[test]
    fn port_retains_upstream_middle_snake_and_minimal_distance_properties() {
        let before_bytes = b"A\nB\nC\nA\nB\nB\nA\n";
        let after_bytes = b"C\nB\nA\nB\nA\nC\n";
        let before = line_table(before_bytes);
        let after = line_table(after_bytes);
        let maximum_d = max_d(before.len(), after.len()).expect("max d");
        let mut forward = Frontier::with_len(maximum_d).expect("forward frontier");
        let mut reverse = Frontier::with_len(maximum_d).expect("reverse frontier");
        let mut clock = FakeClock::fixed(0);
        let mut guard =
            WorkGuard::new(&mut clock, fake_deadlines(), MAX_WORK_UNITS_PER_FILE).expect("guard");
        assert_eq!(
            find_middle_snake(
                &before,
                &after,
                SolveRange {
                    before_start: 0,
                    before_end: before.len(),
                    after_start: 0,
                    after_end: after.len(),
                },
                &mut forward,
                &mut reverse,
                &mut guard,
            )
            .expect("middle snake"),
            (4, 1)
        );

        let mut sequences = Vec::new();
        for len in 0..=4 {
            for value in 0..3usize.pow(len as u32) {
                sequences.push(encode_sequence(value, len));
            }
        }
        for before in &sequences {
            for after in &sequences {
                let mut clock = FakeClock::fixed(0);
                let script = build_exact_script_with_source(
                    ReportingFile::AiSafe(before),
                    ReportingFile::AiSafe(after),
                    DiffLimits::accepted(),
                    fake_deadlines(),
                    &mut clock,
                )
                .unwrap_or_else(|error| {
                    panic!("small exact Myers result: {error:?}; before={before:?} after={after:?}")
                });
                assert_eq!(
                    script.edit_distance(),
                    lcs_edit_distance(before, after),
                    "before={before:?} after={after:?}"
                );
            }
        }
    }

    #[test]
    fn deadline_is_strict_and_fake_clock_is_deterministic() {
        let before = ReportingFile::AiSafe(b"a\nb\n");
        let after = ReportingFile::AiSafe(b"a\nc\n");

        let mut just_before = FakeClock::fixed(9);
        assert!(build_exact_script_with_source(
            before,
            after,
            DiffLimits::accepted(),
            fake_deadlines(),
            &mut just_before,
        )
        .is_ok());

        let mut exactly = FakeClock::fixed(10);
        assert_eq!(
            build_exact_script_with_source(
                before,
                after,
                DiffLimits::accepted(),
                fake_deadlines(),
                &mut exactly,
            ),
            Err(DiffError::DeadlineExceeded)
        );

        for checkpoint in [
            DeadlineCheckpoint::MiddleSnake,
            DeadlineCheckpoint::DivideStep,
            DeadlineCheckpoint::WorkStack,
            DeadlineCheckpoint::Replay,
            DeadlineCheckpoint::Finish,
        ] {
            let occurrence = if checkpoint == DeadlineCheckpoint::WorkStack {
                2
            } else {
                1
            };
            let mut clock = FakeClock::expires_on(checkpoint, occurrence);
            let result = build_exact_script_with_source(
                ReportingFile::AiSafe(b"A\nB\nC\nA\nB\nB\nA\n"),
                ReportingFile::AiSafe(b"C\nB\nA\nB\nA\nC\n"),
                DiffLimits::accepted(),
                fake_deadlines(),
                &mut clock,
            );
            assert_eq!(result, Err(DiffError::DeadlineExceeded), "{checkpoint:?}");
        }

        let mut projection_clock = FakeClock::expires_on(DeadlineCheckpoint::Projection, 1);
        assert_eq!(
            diff_and_regions_with_source(
                before,
                after,
                DiffLimits::accepted(),
                fake_deadlines(),
                &mut projection_clock,
            ),
            Err(DiffError::DeadlineExceeded)
        );
    }

    #[test]
    fn adversarial_middle_snakes_return_deadline_without_fallback() {
        let alternating_before = b"A\nB\n".repeat(256);
        let alternating_after = b"B\nA\n".repeat(256);
        let repeated_before = [
            b"same\n".repeat(128),
            b"old\n".to_vec(),
            b"same\n".repeat(128),
        ]
        .concat();
        let repeated_after = [
            b"same\n".repeat(128),
            b"new\n".to_vec(),
            b"same\n".repeat(128),
        ]
        .concat();
        let shifted_before = [b"left\n".repeat(96), b"right\n".repeat(96)].concat();
        let shifted_after = [b"right\n".repeat(96), b"left\n".repeat(96)].concat();
        let distinct_before = (0..128)
            .flat_map(|index| format!("old-{index}\n").into_bytes())
            .collect::<Vec<_>>();
        let distinct_after = (0..128)
            .flat_map(|index| format!("new-{index}\n").into_bytes())
            .collect::<Vec<_>>();
        let shapes = vec![
            (alternating_before, alternating_after),
            (repeated_before, repeated_after),
            (shifted_before, shifted_after),
            (distinct_before, distinct_after),
            (
                b"A\nB\nC\nA\nB\nB\nA\n".to_vec(),
                b"C\nB\nA\nB\nA\nC\n".to_vec(),
            ),
        ];
        for (before, after) in shapes {
            let mut clock = FakeClock::expires_on(DeadlineCheckpoint::MiddleSnake, 2);
            let result = diff_and_regions_with_source(
                ReportingFile::AiSafe(&before),
                ReportingFile::AiSafe(&after),
                DiffLimits::accepted(),
                fake_deadlines(),
                &mut clock,
            );
            assert_eq!(result, Err(DiffError::DeadlineExceeded));
        }
    }

    #[test]
    fn deterministic_work_and_stack_caps_return_errors_only() {
        let mut work_limits = DiffLimits::accepted();
        work_limits.max_work_units = 4;
        let mut clock = FakeClock::fixed(0);
        assert_eq!(
            build_exact_script_with_source(
                ReportingFile::AiSafe(b"A\nB\nC\n"),
                ReportingFile::AiSafe(b"X\nY\nZ\n"),
                work_limits,
                fake_deadlines(),
                &mut clock,
            ),
            Err(DiffError::WorkBoundExceeded)
        );

        let mut stack_limits = DiffLimits::accepted();
        stack_limits.max_work_stack_items = 1;
        let mut clock = FakeClock::fixed(0);
        assert_eq!(
            build_exact_script_with_source(
                ReportingFile::AiSafe(b"A\nB\nC\nA\n"),
                ReportingFile::AiSafe(b"C\nA\nB\nC\n"),
                stack_limits,
                fake_deadlines(),
                &mut clock,
            ),
            Err(DiffError::WorkBoundExceeded)
        );

        let mut op_limits = DiffLimits::accepted();
        op_limits.max_ops = 1;
        let mut clock = FakeClock::fixed(0);
        assert_eq!(
            build_exact_script_with_source(
                ReportingFile::AiSafe(b"old\n"),
                ReportingFile::AiSafe(b"new\n"),
                op_limits,
                fake_deadlines(),
                &mut clock,
            ),
            Err(DiffError::WorkBoundExceeded)
        );
    }

    #[test]
    fn line_bound_accepts_limit_and_rejects_limit_plus_one() {
        let at_limit = vec![b'\n'; MAX_LOGICAL_LINES_PER_SIDE];
        assert!(present_regions(&at_limit, &at_limit)
            .expect("line limit")
            .is_empty());

        let over_limit = vec![b'\n'; MAX_LOGICAL_LINES_PER_SIDE + 1];
        assert_eq!(
            present_regions(&over_limit, &over_limit),
            Err(DiffError::LineBoundExceeded)
        );
    }

    #[test]
    fn maximum_memory_ledger_is_derived_from_production_structures() {
        let limits = DiffLimits::accepted();
        let ledger = memory_ledger(
            MAX_LOGICAL_LINES_PER_SIDE,
            MAX_LOGICAL_LINES_PER_SIDE,
            true,
            limits,
        )
        .expect("maximum ledger");

        assert_eq!(
            ledger.before_line_spans,
            MAX_LOGICAL_LINES_PER_SIDE * size_of::<LineSpan>()
        );
        assert_eq!(
            ledger.after_line_spans,
            MAX_LOGICAL_LINES_PER_SIDE * size_of::<LineSpan>()
        );
        assert_eq!(ledger.before_line_ranks, 0);
        assert_eq!(ledger.after_line_ranks, 0);
        let frontier_items = max_d(MAX_LOGICAL_LINES_PER_SIDE, MAX_LOGICAL_LINES_PER_SIDE)
            .expect("frontier items")
            * 2;
        assert_eq!(ledger.forward_frontier, frontier_items * size_of::<usize>());
        assert_eq!(ledger.reverse_frontier, frontier_items * size_of::<usize>());
        assert_eq!(
            ledger.work_stack,
            MAX_WORK_STACK_ITEMS * size_of::<WorkItem>()
        );
        assert_eq!(ledger.diff_ops, MAX_DIFF_OPS * size_of::<DiffOp>());
        assert_eq!(ledger.replay_scratch, size_of::<ReplayCursor>());
        assert_eq!(
            ledger.region_projection_scratch,
            MAX_REGIONS_PER_FILE * size_of::<ContentChangeRegionV1>()
        );
        let derived_total = [
            ledger.before_line_spans,
            ledger.after_line_spans,
            ledger.before_line_ranks,
            ledger.after_line_ranks,
            ledger.forward_frontier,
            ledger.reverse_frontier,
            ledger.work_stack,
            ledger.diff_ops,
            ledger.replay_scratch,
            ledger.region_projection_scratch,
            ledger.vector_headers,
        ]
        .into_iter()
        .sum::<usize>();
        assert_eq!(ledger.total, derived_total);
        assert!(ledger.total <= MAX_WORKING_BYTES_PER_FILE, "{ledger:?}");

        let mut constrained = limits;
        constrained.max_working_bytes = memory_ledger(1, 1, true, limits)
            .expect("one-line ledger")
            .total
            .checked_sub(1)
            .expect("nonzero one-line ledger");
        let mut clock = FakeClock::fixed(0);
        assert_eq!(
            build_exact_script_with_source(
                ReportingFile::AiSafe(b"old\n"),
                ReportingFile::AiSafe(b"new\n"),
                constrained,
                fake_deadlines(),
                &mut clock,
            ),
            Err(DiffError::WorkingMemoryExceeded)
        );
    }

    fn fabricated_regions_script(count: usize) -> ExactDiffScript {
        let mut ops = Vec::with_capacity(count * 3);
        for index in 0..count {
            let cursor = u32::try_from(index * 2).expect("bounded fixture cursor");
            ops.push(DiffOp::Delete {
                before_index: cursor,
                before_len: 1,
                after_index: cursor,
            });
            ops.push(DiffOp::Insert {
                before_index: cursor + 1,
                after_index: cursor,
                after_len: 1,
            });
            ops.push(DiffOp::Equal {
                before_index: cursor + 1,
                after_index: cursor + 1,
                len: 1,
            });
        }
        ExactDiffScript {
            ops,
            before_line_count: count * 2,
            after_line_count: count * 2,
        }
    }

    #[test]
    fn per_file_and_aggregate_region_bounds_never_truncate() {
        let mut clock = FakeClock::fixed(0);
        let mut guard = WorkGuard::new(
            &mut clock,
            Deadlines {
                file: u64::MAX,
                aggregate: u64::MAX,
            },
            MAX_WORK_UNITS_PER_FILE,
        )
        .expect("guard");
        let at_limit = project_regions(
            &fabricated_regions_script(MAX_REGIONS_PER_FILE),
            DiffLimits::accepted(),
            &mut guard,
        )
        .expect("region limit");
        assert_eq!(at_limit.len(), MAX_REGIONS_PER_FILE);

        let mut clock = FakeClock::fixed(0);
        let mut guard = WorkGuard::new(
            &mut clock,
            Deadlines {
                file: u64::MAX,
                aggregate: u64::MAX,
            },
            MAX_WORK_UNITS_PER_FILE,
        )
        .expect("guard");
        assert_eq!(
            project_regions(
                &fabricated_regions_script(MAX_REGIONS_PER_FILE + 1),
                DiffLimits::accepted(),
                &mut guard,
            ),
            Err(DiffError::RegionBoundExceeded)
        );

        let future = Instant::now()
            .checked_add(Duration::from_secs(60))
            .expect("future instant");
        let mut budget = ReviewDiffBudget {
            aggregate_deadline: future,
            regions: 0,
        };
        budget
            .accept_regions(MAX_REGIONS_PER_REVIEW)
            .expect("aggregate limit");
        assert_eq!(budget.regions(), MAX_REGIONS_PER_REVIEW);
        assert_eq!(
            budget.accept_regions(1),
            Err(DiffError::AggregateRegionBoundExceeded)
        );
        assert_eq!(budget.regions(), MAX_REGIONS_PER_REVIEW);

        let mut over_budget = ReviewDiffBudget {
            aggregate_deadline: future,
            regions: 0,
        };
        assert_eq!(
            over_budget.accept_regions(MAX_REGIONS_PER_REVIEW + 1),
            Err(DiffError::AggregateRegionBoundExceeded)
        );
        assert_eq!(over_budget.regions(), 0);
    }

    #[test]
    fn aggregate_deadline_rejects_the_next_file_at_equality() {
        let mut just_before = FakeClock::fixed(19);
        let now = just_before.now(DeadlineCheckpoint::ReviewFile);
        assert_eq!(
            select_file_deadlines(now, 29, 20),
            Ok(Deadlines {
                file: 20,
                aggregate: 20,
            })
        );

        let mut exactly = FakeClock::fixed(20);
        let now = exactly.now(DeadlineCheckpoint::ReviewFile);
        assert_eq!(
            select_file_deadlines(now, 30, 20),
            Err(DiffError::DeadlineExceeded)
        );
        assert_eq!(FILE_DEADLINE, Duration::from_millis(250));
        assert_eq!(REVIEW_DEADLINE, Duration::from_secs(5));

        let live = ReviewDiffBudget::start().expect("aggregate controller");
        let deadlines = live.begin_file().expect("next file deadline");
        assert!(deadlines.0.file <= deadlines.0.aggregate);
    }

    fn verify_ops(
        before_bytes: &[u8],
        after_bytes: &[u8],
        ops: &[DiffOp],
    ) -> Result<(), DiffError> {
        let before = line_table(before_bytes);
        let after = line_table(after_bytes);
        let mut clock = FakeClock::fixed(0);
        let mut guard = WorkGuard::new(&mut clock, fake_deadlines(), MAX_WORK_UNITS_PER_FILE)?;
        verify_script(&before, &after, ops, &mut guard)
    }

    #[test]
    fn replay_verifier_rejects_gaps_overlap_mismatch_and_partial_cursors() {
        let valid = [
            DiffOp::Equal {
                before_index: 0,
                after_index: 0,
                len: 1,
            },
            DiffOp::Delete {
                before_index: 1,
                before_len: 1,
                after_index: 1,
            },
            DiffOp::Insert {
                before_index: 2,
                after_index: 1,
                after_len: 1,
            },
        ];
        assert_eq!(verify_ops(b"a\nb\n", b"a\nc\n", &valid), Ok(()));

        let gap = [DiffOp::Delete {
            before_index: 1,
            before_len: 1,
            after_index: 0,
        }];
        assert_eq!(
            verify_ops(b"a\nb\n", b"a\n", &gap),
            Err(DiffError::InvalidScript)
        );

        let overlap = [
            DiffOp::Delete {
                before_index: 0,
                before_len: 1,
                after_index: 0,
            },
            DiffOp::Delete {
                before_index: 0,
                before_len: 1,
                after_index: 0,
            },
            DiffOp::Insert {
                before_index: 2,
                after_index: 0,
                after_len: 1,
            },
        ];
        assert_eq!(
            verify_ops(b"a\nb\n", b"c\n", &overlap),
            Err(DiffError::InvalidScript)
        );

        let unequal_equal = [DiffOp::Equal {
            before_index: 0,
            after_index: 0,
            len: 1,
        }];
        assert_eq!(
            verify_ops(b"a\n", b"b\n", &unequal_equal),
            Err(DiffError::InvalidScript)
        );

        let partial = [DiffOp::Equal {
            before_index: 0,
            after_index: 0,
            len: 1,
        }];
        assert_eq!(
            verify_ops(b"a\nb\n", b"a\nb\n", &partial),
            Err(DiffError::InvalidScript)
        );

        let zero = [DiffOp::Equal {
            before_index: 0,
            after_index: 0,
            len: 0,
        }];
        assert_eq!(verify_ops(b"", b"", &zero), Err(DiffError::InvalidScript));
    }

    #[test]
    fn production_path_uses_instant_and_returns_only_verified_regions() {
        let mut budget = ReviewDiffBudget::start().expect("budget");
        let deadlines = budget.begin_file().expect("file deadline");
        let script = StrictLineDiff::diff(
            ReportingFile::AiSafe(b"before\n"),
            ReportingFile::AiSafe(b"after\n"),
            DiffLimits::accepted(),
            deadlines,
        )
        .expect("production exact script");
        assert_eq!(script.edit_distance(), 2);

        let deadlines = budget.begin_file().expect("second file deadline");
        let regions = StrictLineDiff::regions(
            ReportingFile::AiSafe(b"before\n"),
            ReportingFile::AiSafe(b"after\n"),
            DiffLimits::accepted(),
            deadlines,
        )
        .expect("production regions");
        assert_eq!(regions.len(), 1);
        budget
            .accept_regions(regions.len())
            .expect("aggregate region accounting");
    }

    #[test]
    fn reporting_module_has_no_classifier_or_private_state_dependency() {
        const CLASSIFY: &str = include_str!("classify.rs");
        const ANCHOR: &str = include_str!("anchor.rs");
        const EVENTS: &str = include_str!("events.rs");
        const SOURCE: &str = include_str!("report_diff.rs");
        const CARGO_TOML: &str = include_str!("../../Cargo.toml");
        const CARGO_LOCK: &str = include_str!("../../Cargo.lock");

        for authority_source in [CLASSIFY, ANCHOR, EVENTS] {
            for forbidden in [
                "use super::report_diff",
                "use crate::roundtrip::report_diff",
                "super::report_diff::",
                "crate::roundtrip::report_diff::",
            ] {
                assert!(
                    !authority_source.contains(forbidden),
                    "forbidden reporting dependency: {forbidden}"
                );
            }
        }
        for forbidden in [
            ["super", "::", "classify"].concat(),
            ["super", "::", "anchor"].concat(),
            ["super", "::", "events"].concat(),
            ["super", "::", "capsule"].concat(),
            ["super", "::", "dpapi"].concat(),
            ["std", "::", "fs"].concat(),
        ] {
            assert!(!SOURCE.contains(&forbidden), "forbidden edge: {forbidden}");
        }
        assert!(!CARGO_TOML.contains("similar"));
        assert!(!CARGO_LOCK.contains("name = \"similar\""));
    }
}
