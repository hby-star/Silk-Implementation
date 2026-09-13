use super::{Action, Block, Body, Error, Message, Params, dispersal, rbc::ReliableBroadcast};
use protocol_support::wire::canonical_serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct RoundState {
    rbc: ReliableBroadcast,
    proposal: Option<Block>,
    proposed: bool,
    safe: bool,
    disabled: bool,
    voted: bool,
    timed_out: bool,
    timeout_accept_sent: bool,
    commits: BTreeSet<u32>,
    timeout_votes: BTreeSet<u32>,
    timeout_accepts: BTreeSet<u32>,
}

pub struct SimpleIt {
    params: Params,
    context: [u8; 32],
    node: u32,
    input: Vec<u8>,
    current: u64,
    rounds: BTreeMap<u64, RoundState>,
    decision: Option<u64>,
}

impl SimpleIt {
    pub fn new(
        params: Params,
        context: [u8; 32],
        node: u32,
        input: Vec<u8>,
    ) -> Result<Self, Error> {
        if node as usize >= params.n || input.is_empty() {
            return Err(Error::InvalidParams);
        }
        let mut rounds = BTreeMap::new();
        rounds.insert(
            0,
            RoundState {
                safe: true,
                ..RoundState::default()
            },
        );
        rounds.insert(1, RoundState::default());
        Ok(Self {
            params,
            context,
            node,
            input,
            current: 1,
            rounds,
            decision: None,
        })
    }

    pub fn current_round(&self) -> u64 {
        self.current
    }
    pub fn decided_round(&self) -> Option<u64> {
        self.decision
    }

    pub fn start(&mut self) -> Result<Vec<Action>, Error> {
        let mut actions = vec![Action::EnterRound(1)];
        self.progress(&mut actions)?;
        Ok(actions)
    }

    pub fn receive(&mut self, sender: u32, message: Message) -> Result<Vec<Action>, Error> {
        let mut actions = Vec::new();
        if sender as usize >= self.params.n || message.context != self.context || message.round == 0
        {
            return Ok(actions);
        }
        let round = message.round;
        let state = self.rounds.entry(round).or_default();
        match message.body {
            Body::Commit => {
                state.commits.insert(sender);
            }
            Body::TimeoutVote => {
                state.timeout_votes.insert(sender);
            }
            Body::TimeoutAccept => {
                state.timeout_accepts.insert(sender);
            }
            body => state.rbc.receive(
                self.params,
                self.context,
                round,
                self.node,
                sender,
                body,
                &mut actions,
            ),
        }
        self.advance_subprotocol(round, &mut actions);
        self.progress(&mut actions)?;
        Ok(actions)
    }

    pub fn accept_candidate(
        &mut self,
        round: u64,
        root: [u8; 32],
        accepted: bool,
    ) -> Result<Vec<Action>, Error> {
        let mut actions = Vec::new();
        if let Some(state) = self.rounds.get_mut(&round) {
            state.rbc.accept(root, accepted);
        }
        self.advance_subprotocol(round, &mut actions);
        self.progress(&mut actions)?;
        Ok(actions)
    }

    pub fn timeout(&mut self, round: u64) -> Result<Vec<Action>, Error> {
        let mut actions = Vec::new();
        if round != self.current {
            return Ok(actions);
        }
        let state = self.rounds.entry(round).or_default();
        if !state.voted && !state.timed_out {
            state.timed_out = true;
            self.broadcast(round, Body::TimeoutVote, &mut actions);
        }
        self.progress(&mut actions)?;
        Ok(actions)
    }

    fn broadcast(&self, round: u64, body: Body, actions: &mut Vec<Action>) {
        actions.push(Action::Send {
            receiver: None,
            message: Message {
                context: self.context,
                round,
                body,
            },
        });
    }

    fn advance_subprotocol(&mut self, round: u64, actions: &mut Vec<Action>) {
        let Some(state) = self.rounds.get_mut(&round) else {
            return;
        };
        if let Some(block) = state.rbc.advance(self.params, self.context, round, actions) {
            state.proposal = Some(block);
        }
        // Figure 4: accept on n-f votes OR f+1 accepts; confirm on 2f+1.
        // This remains enabled for old rounds, even after the local timer moves.
        let relay = !state.timeout_accept_sent
            && (state.timeout_votes.len() >= self.params.quorum()
                || state.timeout_accepts.len() > self.params.t);
        if relay {
            state.timeout_accept_sent = true;
        }
        if state.timeout_accepts.len() > 2 * self.params.t {
            state.disabled = true;
        }
        if relay {
            self.broadcast(round, Body::TimeoutAccept, actions);
        }
    }

    fn safe_parent(&self, round: u64, parent: u64) -> bool {
        parent < round
            && self.rounds.get(&parent).is_some_and(|state| state.safe)
            && self
                .rounds
                .range(parent + 1..round)
                .filter(|(_, state)| state.disabled)
                .count() as u64
                == round - parent - 1
    }

    fn first_value(&self, mut round: u64) -> Option<(u64, &Vec<u8>)> {
        let mut first = None;
        while round != 0 {
            let block = self.rounds.get(&round)?.proposal.as_ref()?;
            if let Some(value) = &block.value {
                first = Some((round, value));
            }
            round = block.parent;
        }
        first
    }

    fn progress(&mut self, actions: &mut Vec<Action>) -> Result<(), Error> {
        loop {
            let mut changed = false;
            // Parent numbers decrease strictly, so one ascending pass propagates
            // safety through every currently available chain.
            let known = self
                .rounds
                .keys()
                .copied()
                .filter(|r| *r != 0)
                .collect::<Vec<_>>();
            for round in known {
                let parent = self.rounds[&round].proposal.as_ref().map(|b| b.parent);
                if !self.rounds[&round].safe && parent.is_some_and(|p| self.safe_parent(round, p)) {
                    self.rounds.get_mut(&round).expect("known round").safe = true;
                    changed = true;
                }
            }
            if self.decision.is_none() {
                let committed = self
                    .rounds
                    .iter()
                    .filter(|(_, state)| state.safe && state.commits.len() >= self.params.quorum())
                    .map(|(round, _)| *round)
                    .collect::<Vec<_>>();
                for round in committed {
                    if let Some((proposal_round, value)) = self.first_value(round) {
                        actions.push(Action::Decide {
                            proposal_round,
                            commit_round: round,
                            value: value.clone(),
                        });
                        self.decision = Some(proposal_round);
                        break;
                    }
                }
            }
            // Delivering a value does not terminate Simple-IT. A lagging party
            // may need a later committed descendant to deliver that same value.
            // Keep old RBC/RN states and continue voting until the caller retires
            // the instance under its application/service completion policy.
            let round = self.current;
            if self.params.leader(round) == self.node && !self.rounds[&round].proposed {
                // Every predecessor has become safe or disabled before entering
                // this round, so a highest safe parent exists (possibly genesis).
                if let Some(parent) = self
                    .rounds
                    .range(..round)
                    .rev()
                    .map(|(r, _)| *r)
                    .find(|p| self.safe_parent(round, *p))
                {
                    self.rounds.get_mut(&round).expect("current round").proposed = true;
                    // One application height has only one deliverable value;
                    // descendants of an existing value are empty ordering blocks.
                    let value = self
                        .first_value(parent)
                        .is_none()
                        .then(|| self.input.clone());
                    let encoded = canonical_serialize(&Block { parent, value })
                        .map_err(|_| Error::InvalidPayload)?;
                    for fragment in
                        dispersal::disperse(self.params, &self.context, round, &encoded)?
                    {
                        actions.push(Action::Send {
                            receiver: Some(fragment.index),
                            message: Message {
                                context: self.context,
                                round,
                                body: Body::Disperse(fragment),
                            },
                        });
                    }
                }
            }
            let state = self.rounds.get_mut(&round).expect("current round");
            if state.safe && !state.voted && !state.timed_out {
                state.voted = true;
                self.broadcast(round, Body::Commit, actions);
            }
            let state = &self.rounds[&round];
            if state.disabled || (state.safe && (state.voted || state.timed_out)) {
                self.current = round.checked_add(1).ok_or(Error::RoundOverflow)?;
                self.rounds.entry(self.current).or_default();
                actions.push(Action::EnterRound(self.current));
                changed = true;
            }
            if !changed {
                return Ok(());
            }
        }
    }
}
