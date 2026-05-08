//! Kernel Event Loop — the main loop that drives the OS.
//!
//! Like Linux's core scheduler loop. Processes signals, runs the scheduler,
//! dispatches agent work, handles timers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::interval;

use crate::agent_struct::AgentId;

/// Events that the kernel processes.
#[derive(Debug, Clone)]
pub enum KernelEvent {
    /// An agent was created.
    AgentCreated(AgentId),
    /// An agent exited.
    AgentExited { id: AgentId, code: i32 },
    /// An agent needs scheduling.
    AgentReady(AgentId),
    /// A signal was sent.
    SignalSent { target: AgentId, signal: u8 },
    /// A timer fired.
    TimerFired { id: u64 },
    /// Tool call completed.
    ToolCallDone { agent_id: AgentId, tokens_used: u64 },
    /// Shutdown requested.
    Shutdown,
}

/// Timer entry.
#[derive(Debug, Clone)]
pub struct Timer {
    pub id: u64,
    pub agent_id: AgentId,
    pub fires_at: Instant,
    pub recurring: Option<Duration>,
}

/// The kernel event loop.
pub struct EventLoop {
    event_rx: mpsc::Receiver<KernelEvent>,
    event_tx: mpsc::Sender<KernelEvent>,
    timers: Vec<Timer>,
    next_timer_id: u64,
    tick_count: u64,
    running: bool,
}

impl EventLoop {
    pub fn new() -> (Self, mpsc::Sender<KernelEvent>) {
        let (tx, rx) = mpsc::channel(1024);
        let tx_clone = tx.clone();
        (
            Self {
                event_rx: rx,
                event_tx: tx,
                timers: Vec::new(),
                next_timer_id: 1,
                tick_count: 0,
                running: false,
            },
            tx_clone,
        )
    }

    /// Get a sender to submit events to the kernel.
    pub fn sender(&self) -> mpsc::Sender<KernelEvent> {
        self.event_tx.clone()
    }

    /// Register a timer.
    pub fn set_timer(
        &mut self,
        agent_id: AgentId,
        delay: Duration,
        recurring: Option<Duration>,
    ) -> u64 {
        let id = self.next_timer_id;
        self.next_timer_id += 1;
        self.timers.push(Timer {
            id,
            agent_id,
            fires_at: Instant::now() + delay,
            recurring,
        });
        id
    }

    /// Cancel a timer.
    pub fn cancel_timer(&mut self, timer_id: u64) {
        self.timers.retain(|t| t.id != timer_id);
    }

    /// Process one batch of events (non-blocking).
    pub async fn tick(&mut self) -> Vec<KernelEvent> {
        self.tick_count += 1;
        let mut events = Vec::new();

        // Drain pending events
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }

        // Check timers
        let now = Instant::now();
        let mut fired = Vec::new();
        let mut to_reschedule = Vec::new();

        self.timers.retain(|timer| {
            if now >= timer.fires_at {
                fired.push(KernelEvent::TimerFired { id: timer.id });
                if let Some(interval) = timer.recurring {
                    to_reschedule.push(Timer {
                        id: timer.id,
                        agent_id: timer.agent_id,
                        fires_at: now + interval,
                        recurring: Some(interval),
                    });
                }
                false // remove fired timer
            } else {
                true // keep
            }
        });

        self.timers.extend(to_reschedule);
        events.extend(fired);

        events
    }

    /// Get tick count.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Get pending timer count.
    pub fn timer_count(&self) -> usize {
        self.timers.len()
    }

    /// Stop the event loop.
    pub fn stop(&mut self) {
        self.running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn submit_and_receive_events() {
        let (mut eloop, tx) = EventLoop::new();
        tx.send(KernelEvent::AgentCreated(1)).await.unwrap();
        tx.send(KernelEvent::AgentCreated(2)).await.unwrap();
        let events = eloop.tick().await;
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn timer_fires() {
        let (mut eloop, _tx) = EventLoop::new();
        eloop.set_timer(1, Duration::from_millis(10), None);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let events = eloop.tick().await;
        assert!(events
            .iter()
            .any(|e| matches!(e, KernelEvent::TimerFired { .. })));
        assert_eq!(eloop.timer_count(), 0); // one-shot removed
    }

    #[tokio::test]
    async fn recurring_timer() {
        let (mut eloop, _tx) = EventLoop::new();
        eloop.set_timer(
            1,
            Duration::from_millis(10),
            Some(Duration::from_millis(10)),
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
        let events = eloop.tick().await;
        assert!(!events.is_empty());
        assert_eq!(eloop.timer_count(), 1); // recurring stays
    }

    #[tokio::test]
    async fn cancel_timer() {
        let (mut eloop, _tx) = EventLoop::new();
        let id = eloop.set_timer(1, Duration::from_millis(100), None);
        eloop.cancel_timer(id);
        assert_eq!(eloop.timer_count(), 0);
    }

    #[tokio::test]
    async fn tick_count_increments() {
        let (mut eloop, _tx) = EventLoop::new();
        assert_eq!(eloop.tick_count(), 0);
        eloop.tick().await;
        eloop.tick().await;
        assert_eq!(eloop.tick_count(), 2);
    }
}

// ─── Timer Units (cron-like) ─────────────────────────────────────────────────

/// A scheduled agent execution (like a cron job).
#[derive(Debug, Clone)]
pub struct TimerUnit {
    pub name: String,
    pub agent_name: String,
    pub interval: Duration,
    pub timer_id: u64,
}

impl EventLoop {
    /// Register a timer unit (recurring agent execution).
    pub fn add_timer_unit(&mut self, name: String, agent_name: String, interval: Duration) -> u64 {
        let timer_id = self.set_timer(0, interval, Some(interval));
        timer_id
    }
}
