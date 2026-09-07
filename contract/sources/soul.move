// SPDX-License-Identifier: BUSL-1.1
// Licensor: Northlatch Labs LLC. Change Date: 2029-09-01. Change License: Apache-2.0.
// Built-by: @projectx.sui /|\ · Co-authored-by: Claude
/// The employment record of an agentic company: who works here, under whose authority, on what
/// budget, and whether they are still earning enough to stay.
///
/// # What this is for
///
/// A company whose employees are agents needs three facts on chain rather than in a file: that an
/// agent's mandate has not been rewritten behind the employer's back, that its spending ceiling is
/// enforced by something it cannot argue with, and that failing to earn has a consequence that
/// arrives on a schedule rather than on somebody's mood. A markdown file in a repository carries
/// none of those. This module carries all three.
///
/// # The guarantee, stated plainly
///
/// **No transaction that consults the soul may spend more than the allowance for its epoch.**
///
/// The second half of that sentence matters as much as the first: a payment path that never calls
/// `record_spend` is outside this module's reach. This module holds no coin, moves no coin, and
/// can refuse nothing that does not ask it. The adapter that routes an agent's spending through
/// `record_spend` is separate work; it is not written here and nothing here pretends it exists.
///
/// # Soulbound, and why it is shared rather than owned
///
/// `EmployeeSoul` has `key` and no `store`: it cannot be wrapped, sold, lent or placed in anyone's
/// inventory, and this module publishes no transfer function. It is then SHARED at birth rather
/// than transferred to the agent, which is the one design choice here worth arguing about.
///
/// An address-owned object can only be mutated inside a transaction its owner signs. An employment
/// record whose allowance can only be lowered with the employee's signature is not an employment
/// record. Sharing separates the two authorities cleanly: the employer proves authority by holding
/// `MasterCap`, the employee proves identity by being `ctx.sender()`, and neither needs custody of
/// the other's object to act. The binding to the address survives in `agent`, which is set once at
/// birth and has no setter — the same shape `projectx_social::account` uses when it checks `owner`
/// against the sender rather than relying on who holds the object.
///
/// A shared object also cannot be transferred at all, by anybody, ever. As a soulbinding that is
/// stronger than ownership, not weaker.
///
/// # The metabolism
///
/// An epoch is seven days, aligned to the company's weekly merge. Value and cost are booked
/// against the open epoch by the holder of `MasterCap`, from figures read off chain; nothing here
/// estimates and nothing here can. At epoch close `settle_epoch` compares the two and moves the
/// soul between states with no judgement involved:
///
///   SOLVENT  — earned >= burned. The allowance rises by a quarter of the surplus, to a ceiling.
///   STARVING — first shortfall. The allowance halves, never below the survival minimum and
///              never upward.
///   DYING    — second consecutive shortfall, and every one after it. The allowance halves again.
///
/// On the third consecutive shortfall the soul is **due for retirement**: `is_due_for_retirement`
/// returns true and `EpochSettled` says so. The retirement itself is performed by the holder of
/// `MasterCap` calling `retire`. The chain marks; the employer executes. That split is deliberate
/// — an object's death should require the cap that bore it, not the routine that keeps its books.
///
/// # Retirement is not deletion
///
/// A retired soul keeps its object, its counters and its whole history for ever; no function here
/// deletes one, and none can, because `EmployeeSoul` is shared. Retirement is a state change and a
/// timestamp. The registry entry is released so the address may be given a NEW soul later — an
/// agent that starved because it was badly scoped can be born again, and the record of the first
/// life stays readable beside the second.
///
/// # What pairs with this off chain
///
/// The design pairs a soul with a `projectx_social::account::SocialAccount` opened in the same
/// ceremony with the Mastercontroller as `referrer`. That pairing is deliberately NOT a Move
/// dependency: see the note in `Move.toml`. `born_by` records the lineage here, is checked against
/// nothing, and claims nothing about any other chain object.
module northlatch_soul::soul;

use std::string::String;
use sui::clock::Clock;
use sui::event;
use sui::table::{Self, Table};

// === Constants ===

/// One epoch, in milliseconds. Seven days, aligned to the company's weekly merge.
const EPOCH_MS: u64 = 604_800_000;

/// Consecutive shortfalls after which a soul is due for retirement.
const MAX_STARVING: u8 = 3;

/// The survival minimum: the allowance a shortfall will not cut below — enough to keep reporting
/// and to keep trying. It is a floor, never a raise: a soul already below it is left where it is.
const MIN_ALLOWANCE: u64 = 10_000_000;

/// The spend ceiling. No allowance may exceed this, however profitable the soul. A ceiling only a
/// human can raise is the point of having one.
const MAX_ALLOWANCE: u64 = 1_000_000_000_000;

/// A solvent soul's allowance rises by `surplus / SURPLUS_DIVISOR` at epoch close.
const SURPLUS_DIVISOR: u64 = 4;

/// A mandate digest is a SHA-256 of the agent's instruction file. Fixed length, so a truncated or
/// empty digest cannot be pinned by accident.
const MANDATE_DIGEST_LEN: u64 = 32;

const STATE_SOLVENT: u8 = 0;
const STATE_STARVING: u8 = 1;
const STATE_DYING: u8 = 2;
const STATE_RETIRED: u8 = 3;

// === Errors ===

/// This address already holds a live soul. One employment record per address, as one identity per
/// address on the social side.
const EAlreadySouled: u64 = 1;
/// The sender is not the agent this soul is bound to.
const ENotThisAgent: u64 = 2;
/// The soul is retired. Retired souls are readable for ever and act never again.
const ERetired: u64 = 3;
/// The epoch this soul is in has not ended yet.
const EEpochNotOver: u64 = 4;
/// The spend would take this epoch past its allowance.
const EAllowanceExceeded: u64 = 5;
/// This soul may not act under the company's name.
const EOutwardNotPermitted: u64 = 6;
/// A mandate digest must be exactly 32 bytes.
const EBadDigest: u64 = 7;
/// A soul needs a department.
const EEmptyDepartment: u64 = 8;
/// No live soul is registered for this address.
const ENotSouled: u64 = 9;
/// An allowance above the ceiling is refused rather than silently clamped.
const EAllowanceAboveCeiling: u64 = 10;

// === Types ===

/// The Mastercontroller's authority: mints souls, sets what they may spend and where they may act,
/// re-pins mandates, books the epoch, settles it, and retires. Intended to live behind the same
/// multisig that holds the platform's caps; nothing here assumes that, and nothing here can check
/// it.
public struct MasterCap has key, store {
    id: UID,
}

/// Which address holds which live soul, and the running totals. Shared: the highest-frequency read
/// in the system is "does this address work here", and it should not contend with anything else.
public struct SoulRegistry has key {
    id: UID,
    by_agent: Table<address, ID>,
    minted: u64,
    retired: u64,
}

/// An employee. Soulbound — see the module documentation.
public struct EmployeeSoul has key {
    id: UID,
    /// The address this soul is bound to. Set once, at birth. There is no setter.
    agent: address,
    /// The address that bore it — the Mastercontroller, recorded for lineage. No setter either.
    born_by: address,
    department: String,
    /// SHA-256 of the agent's instruction file at the moment it was hired or last re-pinned. An
    /// agent whose file no longer hashes to this has been rewritten, and the dispatcher is
    /// expected to refuse it until the employer re-pins deliberately.
    mandate_digest: vector<u8>,
    /// The most this soul may spend in one epoch, in the smallest unit of whatever it spends.
    /// Never above `MAX_ALLOWANCE`.
    allowance_per_epoch: u64,
    /// An opaque encoding of what this soul may call, read by the dispatcher, not by this module.
    scope: vector<u8>,
    /// Whether it may act under the company's name. False at birth, always.
    outward: bool,
    epoch_index: u64,
    epoch_started_ms: u64,
    epoch_earned: u64,
    epoch_burned: u64,
    epoch_spent: u64,
    earned_total: u64,
    burned_total: u64,
    spent_total: u64,
    starving_epochs: u8,
    state: u8,
    born_at_ms: u64,
    retired_at_ms: Option<u64>,
}

// === Events ===

public struct SoulBorn has copy, drop {
    soul: ID,
    agent: address,
    born_by: address,
    department: String,
    allowance_per_epoch: u64,
    born_at_ms: u64,
}

public struct AllowanceSet has copy, drop {
    soul: ID,
    agent: address,
    allowance_per_epoch: u64,
    /// True when the epoch's settlement moved it, false when the employer set it by hand.
    by_settlement: bool,
}

public struct SpendRecorded has copy, drop {
    soul: ID,
    agent: address,
    epoch_index: u64,
    amount: u64,
    epoch_spent: u64,
    remaining: u64,
}

public struct MandateRepinned has copy, drop {
    soul: ID,
    agent: address,
    digest: vector<u8>,
}

public struct EpochSettled has copy, drop {
    soul: ID,
    agent: address,
    epoch_index: u64,
    earned: u64,
    burned: u64,
    spent: u64,
    state: u8,
    starving_epochs: u8,
    allowance_per_epoch: u64,
    due_for_retirement: bool,
}

public struct SoulRetired has copy, drop {
    soul: ID,
    agent: address,
    by_starvation: bool,
    earned_total: u64,
    burned_total: u64,
    spent_total: u64,
    retired_at_ms: u64,
}

// === Initialisation ===

fun init(ctx: &mut TxContext) {
    transfer::share_object(SoulRegistry {
        id: object::new(ctx),
        by_agent: table::new(ctx),
        minted: 0,
        retired: 0,
    });
    transfer::public_transfer(MasterCap { id: object::new(ctx) }, ctx.sender());
}

// === Birth ===

/// Hire an address.
///
/// The soul is shared inside this function rather than returned, for the same reason
/// `projectx_social::creator::open_vault` shares its vault: an `EmployeeSoul` has no `store`, so a
/// returned one could not legally be shared by the caller and the transaction would abort on an
/// unused resource — a confusing way to learn the rule.
public fun mint(
    _: &MasterCap,
    registry: &mut SoulRegistry,
    agent: address,
    department: String,
    mandate_digest: vector<u8>,
    allowance_per_epoch: u64,
    scope: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!registry.by_agent.contains(agent), EAlreadySouled);
    assert!(mandate_digest.length() == MANDATE_DIGEST_LEN, EBadDigest);
    assert!(department.length() > 0, EEmptyDepartment);
    assert!(allowance_per_epoch <= MAX_ALLOWANCE, EAllowanceAboveCeiling);

    let now = clock.timestamp_ms();
    let soul = EmployeeSoul {
        id: object::new(ctx),
        agent,
        born_by: ctx.sender(),
        department,
        mandate_digest,
        allowance_per_epoch,
        scope,
        // Never true at birth. Acting under the company's name is granted deliberately, later.
        outward: false,
        epoch_index: 0,
        epoch_started_ms: now,
        epoch_earned: 0,
        epoch_burned: 0,
        epoch_spent: 0,
        earned_total: 0,
        burned_total: 0,
        spent_total: 0,
        starving_epochs: 0,
        state: STATE_SOLVENT,
        born_at_ms: now,
        retired_at_ms: option::none(),
    };
    let soul_id = object::id(&soul);
    registry.by_agent.add(agent, soul_id);
    registry.minted = registry.minted + 1;

    event::emit(SoulBorn {
        soul: soul_id,
        agent,
        born_by: soul.born_by,
        department: soul.department,
        allowance_per_epoch,
        born_at_ms: now,
    });
    transfer::share_object(soul);
}

// === The employer's hand ===

public fun set_allowance(_: &MasterCap, soul: &mut EmployeeSoul, allowance_per_epoch: u64) {
    soul.assert_live();
    assert!(allowance_per_epoch <= MAX_ALLOWANCE, EAllowanceAboveCeiling);
    soul.allowance_per_epoch = allowance_per_epoch;
    event::emit(AllowanceSet {
        soul: object::id(soul),
        agent: soul.agent,
        allowance_per_epoch,
        by_settlement: false,
    });
}

public fun set_scope(_: &MasterCap, soul: &mut EmployeeSoul, scope: vector<u8>) {
    soul.assert_live();
    soul.scope = scope;
}

/// Grant or withdraw the right to act under the company's name.
public fun set_outward(_: &MasterCap, soul: &mut EmployeeSoul, outward: bool) {
    soul.assert_live();
    soul.outward = outward;
}

/// Re-pin the mandate after the employer has read the new instruction file. Until this is called,
/// a rewritten agent no longer matches its soul.
public fun repin_mandate(_: &MasterCap, soul: &mut EmployeeSoul, digest: vector<u8>) {
    soul.assert_live();
    assert!(digest.length() == MANDATE_DIGEST_LEN, EBadDigest);
    soul.mandate_digest = digest;
    event::emit(MandateRepinned { soul: object::id(soul), agent: soul.agent, digest });
}

/// Retire a soul. This is the only way a soul stops working, whether the metabolism marked it due
/// or the employer decided for another reason; `SoulRetired.by_starvation` records which.
///
/// Nothing is deleted. The object, its counters and its history stand for ever; only the registry
/// entry is released, so the address may be hired again as a new soul.
public fun retire(
    _: &MasterCap,
    registry: &mut SoulRegistry,
    soul: &mut EmployeeSoul,
    clock: &Clock,
) {
    soul.assert_live();
    let now = clock.timestamp_ms();
    let by_starvation = soul.starving_epochs >= MAX_STARVING;

    soul.state = STATE_RETIRED;
    soul.retired_at_ms = option::some(now);
    if (registry.by_agent.contains(soul.agent)) {
        registry.by_agent.remove(soul.agent);
    };
    registry.retired = registry.retired + 1;

    event::emit(SoulRetired {
        soul: object::id(soul),
        agent: soul.agent,
        by_starvation,
        earned_total: soul.earned_total,
        burned_total: soul.burned_total,
        spent_total: soul.spent_total,
        retired_at_ms: now,
    });
}

// === The agent's hand ===

/// Record a spend against this epoch's allowance. Aborts if it would exceed it.
///
/// The sender must be the agent: an employment record anybody could spend against would be a worse
/// guard than none, because it would read like one.
public fun record_spend(soul: &mut EmployeeSoul, amount: u64, ctx: &TxContext) {
    soul.assert_live();
    assert!(ctx.sender() == soul.agent, ENotThisAgent);
    // Compared against the remainder rather than summed first: a sum would abort on u64 overflow
    // before this check could refuse it, and an arithmetic abort is not this module's answer.
    assert!(amount <= soul.remaining_allowance(), EAllowanceExceeded);

    soul.epoch_spent = soul.epoch_spent + amount;
    soul.spent_total = soul.spent_total + amount;

    event::emit(SpendRecorded {
        soul: object::id(soul),
        agent: soul.agent,
        epoch_index: soul.epoch_index,
        amount,
        epoch_spent: soul.epoch_spent,
        remaining: soul.remaining_allowance(),
    });
}

/// The check a caller makes before acting under the company's name. Aborts unless this soul holds
/// the permission and the sender is the agent.
public fun assert_outward(soul: &EmployeeSoul, ctx: &TxContext) {
    soul.assert_live();
    assert!(ctx.sender() == soul.agent, ENotThisAgent);
    assert!(soul.outward, EOutwardNotPermitted);
}

/// What this soul may still spend this epoch.
public fun remaining_allowance(soul: &EmployeeSoul): u64 {
    if (soul.epoch_spent >= soul.allowance_per_epoch) 0
    else soul.allowance_per_epoch - soul.epoch_spent
}

// === The books ===

public fun book_earned(_: &MasterCap, soul: &mut EmployeeSoul, amount: u64) {
    soul.assert_live();
    soul.epoch_earned = soul.epoch_earned + amount;
    soul.earned_total = soul.earned_total + amount;
}

public fun book_burned(_: &MasterCap, soul: &mut EmployeeSoul, amount: u64) {
    soul.assert_live();
    soul.epoch_burned = soul.epoch_burned + amount;
    soul.burned_total = soul.burned_total + amount;
}

/// Close the epoch and apply the consequence. No judgement is exercised here and none can be.
///
/// A third consecutive shortfall leaves the soul DYING and due for retirement; it does not retire
/// it. `retire` does that, under `MasterCap`.
public fun settle_epoch(_: &MasterCap, soul: &mut EmployeeSoul, clock: &Clock) {
    soul.assert_live();
    let now = clock.timestamp_ms();
    assert!(now >= soul.epoch_started_ms + EPOCH_MS, EEpochNotOver);

    let earned = soul.epoch_earned;
    let burned = soul.epoch_burned;
    let spent = soul.epoch_spent;

    if (earned >= burned) {
        soul.starving_epochs = 0;
        soul.state = STATE_SOLVENT;
        // Headroom first: `allowance + surplus / 4` can overflow u64 before any clamp sees it.
        let bump = (earned - burned) / SURPLUS_DIVISOR;
        let headroom = MAX_ALLOWANCE - soul.allowance_per_epoch;
        soul.allowance_per_epoch = if (bump >= headroom) MAX_ALLOWANCE
            else soul.allowance_per_epoch + bump;
    } else {
        soul.starving_epochs = soul.starving_epochs + 1;
        // The survival minimum is a floor, not a raise: a soul hired below it stays where it is,
        // because a shortfall must never widen what an agent may spend.
        let floor = if (soul.allowance_per_epoch < MIN_ALLOWANCE) soul.allowance_per_epoch
            else MIN_ALLOWANCE;
        let halved = soul.allowance_per_epoch / 2;
        soul.allowance_per_epoch = if (halved < floor) floor else halved;
        soul.state = if (soul.starving_epochs == 1) STATE_STARVING else STATE_DYING;
    };

    let due = soul.starving_epochs >= MAX_STARVING;
    event::emit(EpochSettled {
        soul: object::id(soul),
        agent: soul.agent,
        epoch_index: soul.epoch_index,
        earned,
        burned,
        spent,
        state: soul.state,
        starving_epochs: soul.starving_epochs,
        allowance_per_epoch: soul.allowance_per_epoch,
        due_for_retirement: due,
    });
    event::emit(AllowanceSet {
        soul: object::id(soul),
        agent: soul.agent,
        allowance_per_epoch: soul.allowance_per_epoch,
        by_settlement: true,
    });

    soul.epoch_index = soul.epoch_index + 1;
    soul.epoch_started_ms = now;
    soul.epoch_earned = 0;
    soul.epoch_burned = 0;
    soul.epoch_spent = 0;
}

// === Internal ===

fun assert_live(soul: &EmployeeSoul) {
    assert!(soul.state != STATE_RETIRED, ERetired);
}

// === Views ===

public fun agent(soul: &EmployeeSoul): address { soul.agent }
public fun born_by(soul: &EmployeeSoul): address { soul.born_by }
public fun department(soul: &EmployeeSoul): &String { &soul.department }
public fun mandate_digest(soul: &EmployeeSoul): &vector<u8> { &soul.mandate_digest }
public fun allowance_per_epoch(soul: &EmployeeSoul): u64 { soul.allowance_per_epoch }
public fun scope(soul: &EmployeeSoul): &vector<u8> { &soul.scope }
public fun outward(soul: &EmployeeSoul): bool { soul.outward }
public fun state(soul: &EmployeeSoul): u8 { soul.state }
public fun starving_epochs(soul: &EmployeeSoul): u8 { soul.starving_epochs }
public fun epoch_index(soul: &EmployeeSoul): u64 { soul.epoch_index }
public fun epoch_started_ms(soul: &EmployeeSoul): u64 { soul.epoch_started_ms }
public fun epoch_earned(soul: &EmployeeSoul): u64 { soul.epoch_earned }
public fun epoch_burned(soul: &EmployeeSoul): u64 { soul.epoch_burned }
public fun epoch_spent(soul: &EmployeeSoul): u64 { soul.epoch_spent }
public fun earned_total(soul: &EmployeeSoul): u64 { soul.earned_total }
public fun burned_total(soul: &EmployeeSoul): u64 { soul.burned_total }
public fun spent_total(soul: &EmployeeSoul): u64 { soul.spent_total }
public fun born_at_ms(soul: &EmployeeSoul): u64 { soul.born_at_ms }
public fun retired_at_ms(soul: &EmployeeSoul): Option<u64> { soul.retired_at_ms }
public fun is_retired(soul: &EmployeeSoul): bool { soul.state == STATE_RETIRED }

/// True when the metabolism has marked this soul for retirement and nobody has performed it yet.
public fun is_due_for_retirement(soul: &EmployeeSoul): bool {
    soul.state != STATE_RETIRED && soul.starving_epochs >= MAX_STARVING
}

public fun works_here(registry: &SoulRegistry, agent: address): bool {
    registry.by_agent.contains(agent)
}

public fun soul_of(registry: &SoulRegistry, agent: address): ID {
    assert!(registry.by_agent.contains(agent), ENotSouled);
    *registry.by_agent.borrow(agent)
}

public fun minted(registry: &SoulRegistry): u64 { registry.minted }
public fun retired_count(registry: &SoulRegistry): u64 { registry.retired }

public fun epoch_ms(): u64 { EPOCH_MS }
public fun max_starving(): u8 { MAX_STARVING }
public fun min_allowance(): u64 { MIN_ALLOWANCE }
public fun max_allowance(): u64 { MAX_ALLOWANCE }
public fun surplus_divisor(): u64 { SURPLUS_DIVISOR }
public fun mandate_digest_len(): u64 { MANDATE_DIGEST_LEN }
public fun state_solvent(): u8 { STATE_SOLVENT }
public fun state_starving(): u8 { STATE_STARVING }
public fun state_dying(): u8 { STATE_DYING }
public fun state_retired(): u8 { STATE_RETIRED }

// === Test-only ===

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
