//! The autonomy boundary: what an agent may do without quorum.
//!
//! This boundary is drawn expressly as **two lists**. Mapping it here as a
//! type instead of as scattered `if` queries in the reconciler has a reason:
//! the boundary is the place at which split brain arises or precisely does not.
//! It has to stand in **one** place, enumerable and individually testable.
//!
//! The direction is deliberately asymmetric. Permitted is what **preserves**
//! running operation; forbidden is what needs a cluster-wide view. An agent
//! without quorum must decide nothing that a second agent on the other side of
//! a partition could decide differently at the same time.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    KeepRunning,
    RestartAssigned,
    SelfFence,
    ReportActual,
    StopUnwanted,
    HoldOnRequirement,
    RestartOnOrder,
    PlaceNew,
    ActivateStandby,
    MutateDesiredState,
    MutateMembership,
    MutatePolicy,
}

impl Action {
    pub const ALL: [Self; 12] = [
        Self::KeepRunning,
        Self::RestartAssigned,
        Self::SelfFence,
        Self::ReportActual,
        Self::StopUnwanted,
        Self::HoldOnRequirement,
        Self::RestartOnOrder,
        Self::PlaceNew,
        Self::ActivateStandby,
        Self::MutateDesiredState,
        Self::MutateMembership,
        Self::MutatePolicy,
    ];

    #[must_use]
    pub fn is_autonomous(self) -> bool {
        match self {
            Self::KeepRunning
            | Self::RestartAssigned
            | Self::SelfFence
            | Self::ReportActual
            | Self::StopUnwanted
            | Self::HoldOnRequirement
            | Self::RestartOnOrder => true,
            Self::PlaceNew
            | Self::ActivateStandby
            | Self::MutateDesiredState
            | Self::MutateMembership
            | Self::MutatePolicy => false,
        }
    }

    #[must_use]
    pub fn quorum_reason(self) -> Option<&'static str> {
        match self {
            Self::KeepRunning
            | Self::RestartAssigned
            | Self::SelfFence
            | Self::ReportActual
            | Self::StopUnwanted
            | Self::HoldOnRequirement
            | Self::RestartOnOrder => None,
            Self::PlaceNew => {
                Some("a placement without a standing assignment needs a cluster-wide view")
            }
            Self::ActivateStandby => {
                Some("activation needs a lease grant with a higher fencing epoch")
            }
            Self::MutateDesiredState | Self::MutateMembership | Self::MutatePolicy => {
                Some("cluster-wide mutations are linearizable and belong in the Raft log")
            }
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeepRunning => "keep a running workload",
            Self::RestartAssigned => "restart an assigned instance",
            Self::SelfFence => "self-fence on lease expiry",
            Self::ReportActual => "report the actual state",
            Self::StopUnwanted => "end a container that is no longer wanted",
            Self::HoldOnRequirement => "hold a dependant back, requirement target failed",
            Self::RestartOnOrder => "restart an instance on a decree",
            Self::PlaceNew => "place anew",
            Self::ActivateStandby => "activate a standby",
            Self::MutateDesiredState => "change the desired state",
            Self::MutateMembership => "change membership",
            Self::MutatePolicy => "change policy",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quorum {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Deferred {
        reason: &'static str,
    },
}

impl Verdict {
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[must_use]
pub fn check(action: Action, quorum: Quorum) -> Verdict {
    if matches!(quorum, Quorum::Available) || action.is_autonomous() {
        return Verdict::Allowed;
    }

    Verdict::Deferred {
        reason: action.quorum_reason().unwrap_or("needs quorum"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autonomous_actions_are_exactly_those_from_adr_0010() {
        let autonomous: Vec<Action> = Action::ALL
            .into_iter()
            .filter(|a| a.is_autonomous())
            .collect();

        assert_eq!(
            autonomous,
            vec![
                Action::KeepRunning,
                Action::RestartAssigned,
                Action::SelfFence,
                Action::ReportActual,
                Action::StopUnwanted,
                Action::HoldOnRequirement,
                Action::RestartOnOrder,
            ]
        );
    }

    #[test]
    fn quorum_bound_actions_are_exactly_those_from_adr_0010() {
        let bound: Vec<Action> = Action::ALL
            .into_iter()
            .filter(|a| !a.is_autonomous())
            .collect();

        assert_eq!(
            bound,
            vec![
                Action::PlaceNew,
                Action::ActivateStandby,
                Action::MutateDesiredState,
                Action::MutateMembership,
                Action::MutatePolicy,
            ]
        );
    }

    #[test]
    fn everything_is_allowed_with_quorum() {
        for action in Action::ALL {
            assert!(
                check(action, Quorum::Available).is_allowed(),
                "{action} should be permitted with quorum"
            );
        }
    }

    #[test]
    fn keeping_a_workload_running_never_needs_quorum() {
        assert!(check(Action::KeepRunning, Quorum::Unavailable).is_allowed());
    }

    #[test]
    fn restarting_an_assigned_instance_never_needs_quorum() {
        assert!(check(Action::RestartAssigned, Quorum::Unavailable).is_allowed());
    }

    #[test]
    fn self_fence_is_allowed_but_activation_is_not() {
        assert!(check(Action::SelfFence, Quorum::Unavailable).is_allowed());
        assert!(!check(Action::ActivateStandby, Quorum::Unavailable).is_allowed());
    }

    #[test]
    fn stopping_what_is_no_longer_wanted_is_allowed_but_placing_is_not() {
        assert!(check(Action::StopUnwanted, Quorum::Unavailable).is_allowed());
        assert!(!check(Action::PlaceNew, Quorum::Unavailable).is_allowed());
    }

    #[test]
    fn an_autonomous_action_carries_no_quorum_reason() {
        assert_eq!(Action::StopUnwanted.quorum_reason(), None);
    }

    #[test]
    fn placing_new_workloads_is_deferred_without_quorum() {
        match check(Action::PlaceNew, Quorum::Unavailable) {
            Verdict::Deferred { reason } => assert!(reason.contains("cluster-wide")),
            Verdict::Allowed => panic!("a new placement must not run without quorum"),
        }
    }

    #[test]
    fn cluster_wide_mutations_are_deferred_without_quorum() {
        for action in [
            Action::MutateDesiredState,
            Action::MutateMembership,
            Action::MutatePolicy,
        ] {
            assert!(
                !check(action, Quorum::Unavailable).is_allowed(),
                "{action} must not run without quorum"
            );
        }
    }

    #[test]
    fn every_quorum_bound_action_states_a_reason() {
        for action in Action::ALL.into_iter().filter(|a| !a.is_autonomous()) {
            assert!(action.quorum_reason().is_some(), "{action} names no reason");
        }
    }

    #[test]
    fn autonomous_actions_carry_no_reason() {
        for action in Action::ALL.into_iter().filter(|a| a.is_autonomous()) {
            assert!(action.quorum_reason().is_none(), "{action} names a reason");
        }
    }
}
