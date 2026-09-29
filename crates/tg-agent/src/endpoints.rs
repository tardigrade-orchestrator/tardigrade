//! The control plane's endpoints, and how the agent switches between them
//! (ADR-0077).
//!
//! # Why this exists
//!
//! Both ways from the node to the control plane go to the **leader** — the
//! session (ADR-0040) and the credential path (ADR-0037) —, and both see a
//! follower do the same thing: it answers with a **referral**. The referral
//! carries an identifier, no address.
//!
//! Measured against two real nodes that was no gap but permanent: the agent knew
//! **one** address, reported "this node does not lead; the leader is 1" and tried
//! the same address again. Twenty-five seconds, no slice — and with that no
//! withdrawal reached it any more (ADR-0025), every single writer fenced
//! (ADR-0064), and after twelve hours no SVID of this node would have been
//! accepted any more (ADR-0014).
//!
//! # Why a pure function
//!
//! It applies to **both** ways. A second version would be two opportunities to
//! interpret it differently — and its outcomes are checkable without a
//! process.

#[derive(Debug, Clone)]
pub(crate) struct Endpoints {
    addresses: Vec<String>,
    at: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    Now,
    AfterWaiting,
}

impl Endpoints {
    pub(crate) fn new(addresses: Vec<String>) -> Option<Self> {
        if addresses.is_empty() {
            return None;
        }
        Some(Self { addresses, at: 0 })
    }

    pub(crate) fn current(&self) -> &str {
        // `advance` keeps the index in range; `first` is the fallback that is
        // never needed -- and it is better than an `unwrap`, for a list here is
        // never empty (see `new`).
        self.addresses
            .get(self.at)
            .or_else(|| self.addresses.first())
            .map_or("", String::as_str)
    }

    pub(crate) fn advance(&mut self) {
        self.at = (self.at + 1) % self.addresses.len();
    }

    pub(crate) fn len(&self) -> usize {
        self.addresses.len()
    }
}

pub(crate) fn next_after_referral(leader: Option<u64>) -> Next {
    if leader.is_some() {
        Next::Now
    } else {
        Next::AfterWaiting
    }
}

#[cfg(test)]
mod tests {
    use super::{Endpoints, Next};

    #[test]
    fn an_empty_list_is_none() {
        assert!(Endpoints::new(Vec::new()).is_none());
    }

    #[test]
    fn a_single_address_stays_where_it_is() {
        let mut one = Endpoints::new(vec!["a".to_owned()]).expect("one");
        assert_eq!(one.current(), "a");
        one.advance();
        assert_eq!(one.current(), "a", "one endpoint stays the same");
    }

    #[test]
    fn the_rotation_wraps_around() {
        let mut all =
            Endpoints::new(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]).expect("three");
        assert_eq!(all.len(), 3);

        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(all.current().to_owned());
            all.advance();
        }
        assert_eq!(seen, vec!["a", "b", "c", "a"]);
    }

    #[test]
    fn a_referral_with_a_leader_does_not_wait() {
        assert_eq!(super::next_after_referral(Some(3)), Next::Now);
        assert_eq!(super::next_after_referral(None), Next::AfterWaiting);
    }
}
