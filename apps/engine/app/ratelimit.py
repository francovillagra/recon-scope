"""
Límites de ritmo en memoria (ventana deslizante).

Valen para UNA instancia del motor (el despliegue actual): los contadores viven en el proceso y se pierden
al reiniciar. Con varias instancias el tope efectivo se multiplica por la cantidad de instancias; para
repartirlo haría falta un almacén compartido (Redis).
"""
import time
from collections import deque
from threading import Lock
from typing import Optional

_registry: list["SlidingWindowLimiter"] = []


class SlidingWindowLimiter:
    """Permite `limit` eventos por clave dentro de los últimos `window_seconds` segundos."""

    def __init__(self, limit: int, window_seconds: float, max_keys: int = 20_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()
        _registry.append(self)

    def _prune(self, key: str, now: float) -> Optional[deque[float]]:
        events = self._events.get(key)
        if events is None:
            return None
        cutoff = now - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        if not events:
            del self._events[key]
            return None
        return events

    def retry_after(self, key: str, now: Optional[float] = None) -> Optional[int]:
        """Segundos hasta que `key` pueda volver a intentar, o None si todavía tiene cupo. No registra nada."""
        now = time.monotonic() if now is None else now
        with self._lock:
            events = self._prune(key, now)
            if events is None or len(events) < self.limit:
                return None
            return max(1, int(events[0] + self.window - now) + 1)

    def record(self, key: str, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            if key not in self._events and len(self._events) >= self.max_keys:
                self._evict(now)
            self._events.setdefault(key, deque()).append(now)

    def hit(self, key: str, now: Optional[float] = None) -> Optional[int]:
        """Registra un evento si hay cupo. Devuelve None si pasó, o los segundos de espera si no."""
        now = time.monotonic() if now is None else now
        wait = self.retry_after(key, now)
        if wait is None:
            self.record(key, now)
        return wait

    def refund(self, key: str) -> None:
        """Devuelve el último cupo reservado de `key` (se reservó con `hit` y al final no se gastó)."""
        with self._lock:
            events = self._events.get(key)
            if events:
                events.pop()
                if not events:
                    del self._events[key]

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()

    def _evict(self, now: float) -> None:
        # Primero lo vencido; si todo está vigente, la clave cuyo último evento es más viejo.
        for key in list(self._events):
            self._prune(key, now)
        if len(self._events) >= self.max_keys:
            oldest = min(self._events, key=lambda k: self._events[k][-1])
            del self._events[oldest]


def reset_all_limiters() -> None:
    for limiter in _registry:
        limiter.reset()
