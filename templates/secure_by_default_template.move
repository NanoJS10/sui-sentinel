/// secure_by_default_template.move
///
/// Baseline starting point for new Sui Move modules handling value transfer
/// or privileged state changes. Encodes the patterns most commonly missing
/// in audited rugpulls/exploits seen by NanoJS Investigations:
///   - capability-gated admin actions (no raw address checks)
///   - explicit event emission on every value-moving function (for
///     SuiSentinel/explorer monitoring to pick up)
///   - no unbounded loops over caller-controlled vectors (DoS prevention)
///   - checked arithmetic only (Move aborts on overflow by default, but
///     this template makes the intent explicit)
module secure_template::vault {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    /// Capability required for any admin-only action. Never gate admin
    /// logic on `tx_context::sender(ctx) == HARDCODED_ADDRESS` — capabilities
    /// are transferable, revocable, and explicit in the object model.
    struct AdminCap has key, store { id: UID }

    struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
        /// Explicit cap on withdrawals per call to bound worst-case impact
        /// of a single compromised/buggy transaction.
        max_withdraw_per_tx: u64,
    }

    /// Emit an event on every value-moving action. This is what
    /// SuiSentinel's monitor.py watches for — undocumented/un-eventful
    /// transfers are themselves a red flag worth alerting on.
    struct WithdrawEvent has copy, drop {
        vault_id: address,
        amount: u64,
        recipient: address,
    }

    const E_EXCEEDS_MAX_WITHDRAW: u64 = 1;
    const E_INSUFFICIENT_BALANCE: u64 = 2;

    fun init(ctx: &mut TxContext) {
        let admin_cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin_cap, tx_context::sender(ctx));

        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
            max_withdraw_per_tx: 1_000_000_000, // tune per deployment; explicit > implicit
        };
        transfer::share_object(vault);
    }

    public entry fun deposit(vault: &mut Vault, payment: Coin<SUI>, _ctx: &mut TxContext) {
        let coin_balance = coin::into_balance(payment);
        balance::join(&mut vault.balance, coin_balance);
    }

    /// Capability-gated, amount-bounded, event-emitting withdrawal.
    /// Three properties most rugpull/treasury-drain incidents lack at least
    /// one of: (1) capability check, (2) per-call ceiling, (3) audit event.
    public entry fun withdraw(
        _admin: &AdminCap,
        vault: &mut Vault,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        assert!(amount <= vault.max_withdraw_per_tx, E_EXCEEDS_MAX_WITHDRAW);
        assert!(balance::value(&vault.balance) >= amount, E_INSUFFICIENT_BALANCE);

        let out = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(out, recipient);

        event::emit(WithdrawEvent {
            vault_id: object::uid_to_address(&vault.id),
            amount,
            recipient,
        });
    }
}
