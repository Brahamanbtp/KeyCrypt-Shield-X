"""Global Workspace Theory architecture for conscious cryptographic agents."""

from __future__ import annotations

from dataclasses import dataclass
from queue import Queue
from threading import RLock
from time import time
from typing import Any, Callable
from uuid import uuid4

from src.utils.logging import get_logger


logger = get_logger("src.consciousness.global_workspace")


FilterFn = Callable[[Any], bool]


@dataclass(frozen=True)
class WorkspaceMessage:
    """Message envelope broadcast into the global workspace."""

    message_id: str
    timestamp: float
    content: Any
    priority: float


class GlobalWorkspace:
    """Queue-backed global workspace with attention and broadcast gating."""

    ATTENTION_THRESHOLD = 0.7
    BROADCAST_THRESHOLD = 0.8

    def __init__(self) -> None:
        self.working_memory: dict[str, Any] = {
            "current_conscious_content": None,
            "current_priority": 0.0,
            "last_broadcast_at": None,
            "last_message_id": None,
            "subscriber_count": 0,
        }
        self._workspace_queue: Queue[WorkspaceMessage] = Queue()
        self._subscriber_queues: dict[str, Queue[WorkspaceMessage]] = {}
        self._subscriber_filters: dict[str, FilterFn | None] = {}
        self._lock = RLock()

        logger.info(
            "global workspace initialized attention_threshold={attention_threshold} "
            "broadcast_threshold={broadcast_threshold}",
            attention_threshold=self.ATTENTION_THRESHOLD,
            broadcast_threshold=self.BROADCAST_THRESHOLD,
        )

    def subscribe_to_workspace(
        self,
        module_id: str,
        filter_fn: FilterFn | None = None,
    ) -> Queue[WorkspaceMessage]:
        """Register a module and return its message queue for workspace broadcasts."""
        normalized_module_id = module_id.strip()
        if not normalized_module_id:
            raise ValueError("module_id must be non-empty")

        with self._lock:
            queue: Queue[WorkspaceMessage] = self._subscriber_queues.get(normalized_module_id, Queue())
            self._subscriber_queues[normalized_module_id] = queue
            self._subscriber_filters[normalized_module_id] = filter_fn
            self.working_memory["subscriber_count"] = len(self._subscriber_queues)

            logger.info(
                "workspace subscription added module_id={module_id} subscriber_count={subscriber_count}",
                module_id=normalized_module_id,
                subscriber_count=self.working_memory["subscriber_count"],
            )

            return queue

    def attention_mechanism(self, competing_signals: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Select the highest-priority signal if it exceeds the attention threshold."""
        if not competing_signals:
            logger.debug("attention_mechanism invoked with no signals")
            return None

        selected = max(competing_signals, key=lambda item: float(item.get("priority", 0.0)))
        selected_priority = float(selected.get("priority", 0.0))

        if selected_priority < self.ATTENTION_THRESHOLD:
            logger.debug(
                "attention signal below threshold priority={priority} threshold={threshold}",
                priority=selected_priority,
                threshold=self.ATTENTION_THRESHOLD,
            )
            return None

        logger.info(
            "attention selected signal priority={priority} threshold={threshold}",
            priority=selected_priority,
            threshold=self.ATTENTION_THRESHOLD,
        )

        with self._lock:
            self.working_memory["current_conscious_content"] = selected.get("content", selected)
            self.working_memory["current_priority"] = selected_priority
            logger.debug("working_memory updated after attention state={state}", state=self.working_memory)

        return selected

    def broadcast_to_workspace(self, content: Any, priority: float) -> bool:
        """Broadcast content to subscribed modules using priority-based gating."""
        resolved_priority = float(priority)
        if resolved_priority < 0.0 or resolved_priority > 1.0:
            raise ValueError("priority must be between 0.0 and 1.0")

        if resolved_priority < self.BROADCAST_THRESHOLD:
            logger.info(
                "broadcast skipped below threshold priority={priority} threshold={threshold}",
                priority=resolved_priority,
                threshold=self.BROADCAST_THRESHOLD,
            )
            return False

        message = WorkspaceMessage(
            message_id=str(uuid4()),
            timestamp=time(),
            content=content,
            priority=resolved_priority,
        )

        with self._lock:
            self._workspace_queue.put(message)
            delivered = 0

            for module_id, module_queue in self._subscriber_queues.items():
                filter_fn = self._subscriber_filters.get(module_id)
                if filter_fn is not None and not filter_fn(content):
                    continue
                module_queue.put(message)
                delivered += 1

            self.working_memory.update(
                {
                    "current_conscious_content": content,
                    "current_priority": resolved_priority,
                    "last_broadcast_at": message.timestamp,
                    "last_message_id": message.message_id,
                }
            )

            logger.info(
                "broadcast delivered message_id={message_id} priority={priority} "
                "delivered_modules={delivered_modules}",
                message_id=message.message_id,
                priority=resolved_priority,
                delivered_modules=delivered,
            )
            logger.debug("working_memory updated state={state}", state=self.working_memory)

        return True

    def pending_workspace_messages(self) -> int:
        """Return number of queued workspace messages."""
        return self._workspace_queue.qsize()


__all__ = ["GlobalWorkspace", "WorkspaceMessage"]
