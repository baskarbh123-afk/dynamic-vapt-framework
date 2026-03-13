"""
core/async_executor.py

Parallel worker pool execution engine.
Supports asyncio-based concurrent task execution with:
  - Priority queues (P0-P4)
  - Per-host rate limiting
  - Automatic retry with exponential backoff
  - Worker health monitoring
  - Task progress callbacks

Architecture reference: ARCHITECTURE.md § 4 "Parallel Scanning Engine"
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Enums / Constants
# ------------------------------------------------------------------

class TaskPriority(IntEnum):
    """Higher value = higher priority (P0 is most urgent)."""
    P0_CRITICAL = 50    # Immediate validation of critical findings
    P1_ACTIVE = 40      # Current active scan phase
    P2_BACKGROUND = 30  # Continuous monitoring tasks
    P3_HISTORICAL = 20  # Historical data processing
    P4_MAINTENANCE = 10 # Cleanup / indexing


MAX_RETRIES = 3
BASE_BACKOFF = 2.0   # seconds
MAX_BACKOFF = 60.0   # seconds


# ------------------------------------------------------------------
# Task definition
# ------------------------------------------------------------------

@dataclass(order=True)
class Task:
    """
    A unit of work for the async executor.

    The `sort_index` field drives priority-queue ordering:
    higher priority = lower sort_index = executes first.
    """
    sort_index: float = field(init=False, repr=False)
    priority: TaskPriority = TaskPriority.P1_ACTIVE
    task_id: str = ""
    coro_fn: Callable[..., Coroutine] = field(default=None, compare=False)
    args: tuple = field(default_factory=tuple, compare=False)
    kwargs: dict = field(default_factory=dict, compare=False)
    host: str = ""          # Used for per-host rate limiting
    retries: int = 0
    max_retries: int = MAX_RETRIES
    enqueued_at: float = field(default_factory=time.monotonic, compare=False)
    result: Any = field(default=None, compare=False)
    error: Optional[Exception] = field(default=None, compare=False)
    completed: bool = field(default=False, compare=False)

    def __post_init__(self):
        # Lower numeric value = higher priority in asyncio PriorityQueue (min-heap)
        # Negate priority so highest priority tasks sort first
        self._sequence = id(self)
        self.sort_index = (-self.priority.value, self.enqueued_at)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.enqueued_at


# ------------------------------------------------------------------
# Worker Stats
# ------------------------------------------------------------------

@dataclass
class WorkerStats:
    worker_id: int
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_retried: int = 0
    total_duration: float = 0.0
    last_active: float = field(default_factory=time.monotonic)

    @property
    def avg_task_duration(self) -> float:
        if self.tasks_completed == 0:
            return 0.0
        return self.total_duration / self.tasks_completed

    def to_dict(self) -> dict:
        return {
            "worker_id": self.worker_id,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "tasks_retried": self.tasks_retried,
            "avg_task_duration_s": round(self.avg_task_duration, 3),
        }


# ------------------------------------------------------------------
# Async Executor
# ------------------------------------------------------------------

class AsyncExecutor:
    """
    Priority-based async worker pool for parallel security tool execution.

    Example:
        executor = AsyncExecutor(max_workers=50, rate_limit_rps=10)
        await executor.start()

        task = Task(
            task_id="recon-001",
            coro_fn=run_subfinder,
            args=("example.com",),
            priority=TaskPriority.P1_ACTIVE,
            host="example.com",
        )
        await executor.submit(task)
        result = await executor.wait_for(task.task_id)
        await executor.stop()
    """

    def __init__(
        self,
        max_workers: int = 50,
        rate_limit_rps: float = 10.0,
        on_task_complete: Optional[Callable[[Task], None]] = None,
    ):
        self.max_workers = max_workers
        self.rate_limit_rps = rate_limit_rps
        self.on_task_complete = on_task_complete

        self._queue: asyncio.PriorityQueue = None
        self._workers: list[asyncio.Task] = []
        self._tasks_by_id: dict[str, Task] = {}
        self._completion_events: dict[str, asyncio.Event] = {}
        self._worker_stats: dict[int, WorkerStats] = {}
        self._rate_limiters: dict[str, float] = defaultdict(float)  # host → last_request_time
        self._running = False
        self._semaphore: asyncio.Semaphore = None

    async def start(self):
        """Start the worker pool."""
        self._queue = asyncio.PriorityQueue()
        self._semaphore = asyncio.Semaphore(self.max_workers)
        self._running = True

        for i in range(self.max_workers):
            self._worker_stats[i] = WorkerStats(worker_id=i)
            worker = asyncio.create_task(self._worker_loop(i), name=f"worker-{i}")
            self._workers.append(worker)

        logger.info(f"[AsyncExecutor] Started {self.max_workers} workers (rate={self.rate_limit_rps} rps)")

    async def stop(self, timeout: float = 30.0):
        """Gracefully stop: drain queue then cancel workers."""
        self._running = False
        # Signal all workers to exit
        for _ in range(self.max_workers):
            await self._queue.put((0, None))  # Sentinel

        try:
            await asyncio.wait_for(
                asyncio.gather(*self._workers, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("[AsyncExecutor] Timeout waiting for workers to stop, cancelling.")
            for worker in self._workers:
                worker.cancel()

        logger.info(f"[AsyncExecutor] Stopped. Stats: {self.get_stats()}")

    async def submit(self, task: Task) -> None:
        """Add a task to the priority queue."""
        self._tasks_by_id[task.task_id] = task
        self._completion_events[task.task_id] = asyncio.Event()
        await self._queue.put((task.sort_index, task))
        logger.debug(f"[AsyncExecutor] Queued task {task.task_id} (priority={task.priority.name})")

    async def submit_many(self, tasks: list[Task]) -> None:
        """Add multiple tasks to the queue."""
        for task in tasks:
            await self.submit(task)

    async def wait_for(self, task_id: str, timeout: float = 300.0) -> Optional[Task]:
        """Block until a specific task completes. Returns the Task with result/error."""
        event = self._completion_events.get(task_id)
        if not event:
            return None
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"[AsyncExecutor] Timeout waiting for task {task_id}")
        return self._tasks_by_id.get(task_id)

    async def wait_all(self, timeout: float = 600.0) -> list[Task]:
        """Wait for all currently queued tasks to complete."""
        task_ids = list(self._completion_events.keys())
        if not task_ids:
            return []

        events = [self._completion_events[tid] for tid in task_ids if tid in self._completion_events]
        try:
            await asyncio.wait_for(
                asyncio.gather(*[e.wait() for e in events]),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("[AsyncExecutor] Timeout waiting for all tasks")

        return [self._tasks_by_id[tid] for tid in task_ids if tid in self._tasks_by_id]

    def get_stats(self) -> dict:
        """Return aggregate executor statistics."""
        total_completed = sum(s.tasks_completed for s in self._worker_stats.values())
        total_failed = sum(s.tasks_failed for s in self._worker_stats.values())
        total_retried = sum(s.tasks_retried for s in self._worker_stats.values())
        queue_depth = self._queue.qsize() if self._queue else 0

        return {
            "workers": self.max_workers,
            "queue_depth": queue_depth,
            "total_completed": total_completed,
            "total_failed": total_failed,
            "total_retried": total_retried,
            "worker_details": [s.to_dict() for s in self._worker_stats.values()],
        }

    # ------------------------------------------------------------------
    # Internal worker loop
    # ------------------------------------------------------------------

    async def _worker_loop(self, worker_id: int):
        """Main loop for a single worker."""
        stats = self._worker_stats[worker_id]

        while self._running:
            try:
                _, task = await asyncio.wait_for(self._queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue

            if task is None:  # Sentinel — stop signal
                self._queue.task_done()
                break

            stats.last_active = time.monotonic()
            start = time.monotonic()

            try:
                # Per-host rate limiting
                await self._enforce_rate_limit(task.host)

                # Execute the coroutine
                task.result = await task.coro_fn(*task.args, **task.kwargs)
                task.completed = True
                stats.tasks_completed += 1
                stats.total_duration += time.monotonic() - start

                logger.debug(
                    f"[Worker-{worker_id}] Completed {task.task_id} "
                    f"in {time.monotonic() - start:.2f}s"
                )

            except Exception as exc:
                task.error = exc
                logger.warning(f"[Worker-{worker_id}] Task {task.task_id} failed: {exc}")

                if task.retries < task.max_retries:
                    task.retries += 1
                    backoff = min(BASE_BACKOFF ** task.retries, MAX_BACKOFF)
                    logger.debug(
                        f"[Worker-{worker_id}] Retrying {task.task_id} "
                        f"(attempt {task.retries}/{task.max_retries}) after {backoff:.1f}s"
                    )
                    await asyncio.sleep(backoff)
                    # Requeue with same priority
                    await self._queue.put((task.sort_index, task))
                    self._queue.task_done()
                    stats.tasks_retried += 1
                    continue
                else:
                    task.completed = True
                    stats.tasks_failed += 1

            finally:
                self._queue.task_done()

                # Signal completion
                event = self._completion_events.get(task.task_id)
                if event:
                    event.set()

                # Call completion callback
                if self.on_task_complete and task.completed:
                    try:
                        self.on_task_complete(task)
                    except Exception as cb_err:
                        logger.debug(f"Completion callback error: {cb_err}")

    async def _enforce_rate_limit(self, host: str):
        """Enforce per-host rate limiting using token bucket model."""
        if not host or self.rate_limit_rps <= 0:
            return

        min_interval = 1.0 / self.rate_limit_rps
        now = time.monotonic()
        last = self._rate_limiters.get(host, 0.0)
        elapsed = now - last

        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            await asyncio.sleep(wait_time)

        self._rate_limiters[host] = time.monotonic()


# ------------------------------------------------------------------
# Convenience helpers
# ------------------------------------------------------------------

def run_sync(coro):
    """Run an async coroutine synchronously (for integration with sync code)."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're inside an event loop (e.g., Jupyter) — use thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


async def run_tasks_parallel(
    coro_fn: Callable,
    items: list[Any],
    max_concurrency: int = 50,
    rate_limit_rps: float = 10.0,
    host_fn: Optional[Callable[[Any], str]] = None,
) -> list[Any]:
    """
    Convenience function: run a coroutine against a list of items in parallel.

    Args:
        coro_fn: Async function to call with each item.
        items: List of inputs.
        max_concurrency: Max concurrent executions.
        rate_limit_rps: Rate limit per host.
        host_fn: Optional function to extract hostname from item (for rate limiting).

    Returns:
        List of results in the same order as items.
    """
    semaphore = asyncio.Semaphore(max_concurrency)
    rate_limiters: dict[str, float] = defaultdict(float)
    min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0

    async def bounded_run(item):
        host = host_fn(item) if host_fn else ""
        async with semaphore:
            if host and min_interval > 0:
                now = time.monotonic()
                last = rate_limiters.get(host, 0.0)
                wait = min_interval - (now - last)
                if wait > 0:
                    await asyncio.sleep(wait)
                rate_limiters[host] = time.monotonic()

            try:
                return await coro_fn(item)
            except Exception as e:
                logger.debug(f"Task failed for {item}: {e}")
                return None

    results = await asyncio.gather(*[bounded_run(item) for item in items])
    return list(results)
