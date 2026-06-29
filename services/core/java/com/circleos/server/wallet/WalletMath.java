package com.circleos.server.wallet;

/**
 * Pure money arithmetic for the SDPKT wallet — no Android dependencies, fully
 * unit-testable off-device. All amounts in cents (long). This is the single
 * source of truth for the balance transitions that ShongololoWalletService
 * performs (send / receive / settle / daily limits), extracted so the money
 * logic can be proven correct with a standalone javac/java unit test.
 */
final class WalletMath {

    static final long DAY_MS = 24L * 60 * 60 * 1000;

    final long perTapCents;
    final long lockPerTapCents;
    final long dailyLimitCents;

    long available;
    long pendingIn;
    long pendingOut;
    long dailySpent;
    long dailyEpochDay;

    WalletMath(long perTapCents, long lockPerTapCents, long dailyLimitCents) {
        this.perTapCents = perTapCents;
        this.lockPerTapCents = lockPerTapCents;
        this.dailyLimitCents = dailyLimitCents;
    }

    /** Reset the daily-spend counter when the calendar day changes. */
    void rolloverDay(long nowMs) {
        long day = nowMs / DAY_MS;
        if (day != dailyEpochDay) {
            dailyEpochDay = day;
            dailySpent = 0;
        }
    }

    /** Headroom against today's cap. */
    long dailyRemaining() {
        return Math.max(0, dailyLimitCents - dailySpent);
    }

    /** Returns the reason a send is blocked, or null if it is allowed. */
    String checkSend(long amountCents, boolean lockScreen, long nowMs) {
        rolloverDay(nowMs);
        if (amountCents <= 0) return "invalid amount";
        long perTap = lockScreen ? lockPerTapCents : perTapCents;
        if (amountCents > perTap) return "over per-tap limit";
        if (amountCents > dailyRemaining()) return "over daily limit";
        if (amountCents > available) return "insufficient funds";
        return null;
    }

    /** Commit an outgoing send: debit available, reserve as pending-out, count toward daily. */
    void finalizeSend(long amountCents, long nowMs) {
        rolloverDay(nowMs);
        available = Math.max(0, available - amountCents);
        pendingOut += amountCents;
        dailySpent += amountCents;
    }

    /** Accept an incoming transfer: held as pending-in until settled. */
    void acceptRecv(long amountCents) {
        pendingIn += amountCents;
    }

    /** Settlement cleared an outgoing tx (funds have truly left). */
    void settleSend(long amountCents) {
        pendingOut = Math.max(0, pendingOut - amountCents);
    }

    /** Settlement cleared an incoming tx → the held funds become spendable. */
    void settleRecv(long amountCents) {
        pendingIn = Math.max(0, pendingIn - amountCents);
        available += amountCents;
    }
}
