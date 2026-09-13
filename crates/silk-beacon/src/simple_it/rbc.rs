use super::{Action, Block, Body, Message, Params, dispersal};
use protocol_support::wire::canonical_deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct RootState {
    payload_len: Option<u32>,
    fragments: BTreeMap<usize, Vec<u8>>,
    echoes: BTreeSet<u32>,
    readies: BTreeSet<u32>,
    attempted: bool,
    candidate: Option<Block>,
    validated: bool,
}

#[derive(Default)]
pub(super) struct ReliableBroadcast {
    roots: BTreeMap<[u8; 32], RootState>,
    echoed: bool,
    ready: bool,
    delivered: bool,
    echo_senders: BTreeSet<u32>,
    ready_senders: BTreeSet<u32>,
}

impl ReliableBroadcast {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn receive(
        &mut self,
        params: Params,
        context: [u8; 32],
        round: u64,
        node: u32,
        sender: u32,
        body: Body,
        actions: &mut Vec<Action>,
    ) {
        match body {
            Body::Disperse(fragment) => {
                if sender != params.leader(round)
                    || self.echoed
                    || fragment.index != node
                    || !dispersal::verify_fragment(params, &context, round, &fragment)
                {
                    return;
                }
                self.echoed = true;
                actions.push(Action::Send {
                    receiver: None,
                    message: Message {
                        context,
                        round,
                        body: Body::Echo(fragment),
                    },
                });
            }
            Body::Echo(fragment) => {
                if self.echo_senders.contains(&sender)
                    || fragment.index != sender
                    || !dispersal::verify_fragment(params, &context, round, &fragment)
                {
                    return;
                }
                self.echo_senders.insert(sender);
                let state = self.roots.entry(fragment.root).or_default();
                // Length is bound inside every Merkle leaf. Inconsistent
                // metadata must not alter a root already under reconstruction.
                if state
                    .payload_len
                    .is_some_and(|length| length != fragment.payload_len)
                {
                    return;
                }
                state.payload_len = Some(fragment.payload_len);
                state.echoes.insert(sender);
                if !state.attempted {
                    state.fragments.insert(sender as usize, fragment.shard);
                }
            }
            Body::Ready(root) => {
                if !self.ready_senders.insert(sender) {
                    return;
                }
                self.roots.entry(root).or_default().readies.insert(sender);
            }
            _ => {}
        }
    }

    pub(super) fn accept(&mut self, root: [u8; 32], accepted: bool) {
        if let Some(state) = self.roots.get_mut(&root) {
            // A callback is valid only after reconstructing and parsing this
            // exact root. The driver cannot authorize arbitrary control votes.
            if state.candidate.is_some() {
                state.validated = accepted;
            }
        }
    }

    pub(super) fn advance(
        &mut self,
        params: Params,
        context: [u8; 32],
        round: u64,
        actions: &mut Vec<Action>,
    ) -> Option<Block> {
        for (root, state) in &mut self.roots {
            if !state.attempted && state.fragments.len() >= params.data_shards() {
                state.attempted = true;
                let result = dispersal::recover(
                    params,
                    &context,
                    round,
                    *root,
                    state.payload_len.expect("fragments contain length"),
                    &state.fragments,
                );
                state.fragments.clear();
                if let Ok(payload) = result
                    && let Ok(block) = canonical_deserialize::<Block>(&payload)
                    && block.parent < round
                {
                    if let Some(value) = &block.value {
                        actions.push(Action::Validate {
                            round,
                            root: *root,
                            value: value.clone(),
                        });
                    } else {
                        state.validated = true;
                    }
                    state.candidate = Some(block);
                }
            }
            if !self.ready
                && ((state.echoes.len() >= params.quorum() && state.validated)
                    || state.readies.len() > params.t)
            {
                self.ready = true;
                actions.push(Action::Send {
                    receiver: None,
                    message: Message {
                        context,
                        round,
                        body: Body::Ready(*root),
                    },
                });
            }
            if !self.delivered && state.validated && state.readies.len() >= params.quorum() {
                self.delivered = true;
                actions.push(Action::RbDelivered(round));
                return state.candidate.take();
            }
        }
        None
    }
}
