//! RFC 8628 device authorization polling.

use std::future::Future;
use std::time::Duration;

/// The default polling interval when the server does not send one (RFC 8628 section 3.2).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

/// Added to the interval on each `slow_down` (RFC 8628 section 3.5).
pub const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// The outcome of one token request.
#[derive(Debug)]
pub enum Poll<T> {
    Pending,
    SlowDown,
    /// The device code expired before it was approved.
    Expired,
    Ready(T),
}

/// Why polling stopped without a token.
#[derive(Debug)]
pub enum PollError<E> {
    Expired,
    Failed(E),
}

/// Polls `attempt` every `interval` until it is ready, fails, or `expires_in` passes.
pub async fn poll<T, E, F, Fut>(
    interval: Duration,
    expires_in: Duration,
    mut attempt: F,
) -> Result<T, PollError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Poll<T>, E>>,
{
    let deadline = tokio::time::Instant::now() + expires_in;
    let mut interval = if interval.is_zero() {
        DEFAULT_INTERVAL
    } else {
        interval
    };
    loop {
        tokio::time::sleep(interval).await;
        if tokio::time::Instant::now() >= deadline {
            return Err(PollError::Expired);
        }
        match attempt().await.map_err(PollError::Failed)? {
            Poll::Ready(value) => return Ok(value),
            Poll::Pending => {}
            Poll::SlowDown => interval += SLOW_DOWN_STEP,
            Poll::Expired => return Err(PollError::Expired),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[tokio::test(start_paused = true)]
    async fn polls_until_ready_and_backs_off_on_slow_down() {
        let script = RefCell::new(vec![Poll::Ready(7), Poll::SlowDown, Poll::Pending]);
        let start = tokio::time::Instant::now();
        let calls = RefCell::new(Vec::new());
        let value = poll(Duration::from_secs(1), Duration::from_secs(600), || {
            calls.borrow_mut().push(start.elapsed().as_secs());
            let next = script.borrow_mut().pop().unwrap();
            async move { Ok::<_, ()>(next) }
        })
        .await
        .unwrap();
        assert_eq!(value, 7);
        // 1 s, then 1 s, then 1 + 5 s after the slow_down.
        assert_eq!(*calls.borrow(), [1, 2, 8]);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_at_the_deadline() {
        let result = poll(Duration::from_secs(2), Duration::from_secs(5), || async {
            Ok::<Poll<()>, ()>(Poll::Pending)
        })
        .await;
        assert!(matches!(result, Err(PollError::Expired)));
    }

    #[tokio::test(start_paused = true)]
    async fn propagates_expiry_and_failures() {
        let expired = poll(Duration::ZERO, Duration::from_secs(60), || async {
            Ok::<Poll<()>, ()>(Poll::Expired)
        })
        .await;
        assert!(matches!(expired, Err(PollError::Expired)));
        let failed = poll(Duration::ZERO, Duration::from_secs(60), || async {
            Err::<Poll<()>, _>("boom")
        })
        .await;
        assert!(matches!(failed, Err(PollError::Failed("boom"))));
    }
}
