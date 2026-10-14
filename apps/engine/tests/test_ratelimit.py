from app.ratelimit import SlidingWindowLimiter


def test_allows_up_to_the_limit_then_blocks_with_a_wait():
    limiter = SlidingWindowLimiter(limit=3, window_seconds=60)
    assert [limiter.hit("a", now=t) for t in (0, 1, 2)] == [None, None, None]
    wait = limiter.hit("a", now=3)
    assert wait is not None and 57 <= wait <= 58


def test_each_key_has_its_own_budget():
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60)
    assert limiter.hit("a", now=0) is None
    assert limiter.hit("a", now=1) is not None
    assert limiter.hit("b", now=1) is None


def test_window_slides():
    limiter = SlidingWindowLimiter(limit=2, window_seconds=10)
    limiter.hit("a", now=0)
    limiter.hit("a", now=5)
    assert limiter.hit("a", now=9) is not None
    assert limiter.hit("a", now=10.5) is None  # el evento de t=0 ya salió de la ventana
    assert limiter.hit("a", now=11) is not None  # t=5 y t=10.5 siguen dentro


def test_retry_after_does_not_consume_budget():
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60)
    for _ in range(5):
        assert limiter.retry_after("a", now=0) is None
    limiter.record("a", now=0)
    assert limiter.retry_after("a", now=1) is not None


def test_clear_forgets_a_key():
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60)
    limiter.hit("a", now=0)
    limiter.clear("a")
    assert limiter.hit("a", now=1) is None


def test_memory_is_bounded():
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60, max_keys=100)
    for i in range(1000):
        limiter.hit(f"k{i}", now=float(i) / 100)
    assert len(limiter._events) <= 100
