//! AI Agent OS Integration & Property-Based Tests
//!
//! This crate contains integration tests and property-based tests
//! that validate cross-crate behavior and correctness properties.

#[cfg(test)]
mod agent_lifecycle_props;

#[cfg(test)]
mod scheduler_props;

#[cfg(test)]
mod context_props;

#[cfg(test)]
mod memory_props;

#[cfg(test)]
mod permission_props;

#[cfg(test)]
mod sandbox_props;

#[cfg(test)]
mod connector_props;

#[cfg(test)]
mod module_props;

#[cfg(test)]
mod ipc_props;

#[cfg(test)]
mod observability_props;

#[cfg(test)]
mod shutdown_props;

#[cfg(test)]
mod prerequisite_props;

#[cfg(test)]
mod notification_props;

#[cfg(test)]
mod e2e_pipeline;

#[cfg(test)]
mod edge_cases;

#[cfg(test)]
mod os_enforcement;
