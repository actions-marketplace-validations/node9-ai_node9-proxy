// What the user is told when the gate asks and nobody answers.
//
// This line is the highest-intent moment the product has: work has just been
// stopped, and the person is looking straight at the reason. Until now it said
// only that the action was auto-denied, with no way out, and a real user
// (2026-07 to 2026-09) received it 151 times over two months without ever
// reaching the dashboard. Every other funnel surface asks for effort against a
// future promise; this one can offer a fix for a present problem.
//
// It points at `node9 login` rather than `node9 connect` deliberately:
// `login` with no argument opens the browser and needs nothing in advance,
// while `connect` requires a token minted in the dashboard, which means being
// in the dashboard already in order to connect to it.
import { describe, it, expect } from 'vitest';
import { approvalTimeoutReason } from '../auth/orchestrator';

describe('the approval-timeout message', () => {
  it('still says what happened and how long it waited', () => {
    const r = approvalTimeoutReason(120_000);
    expect(r).toContain('120s');
    expect(r).toMatch(/auto-denied/i);
  });

  it('tells the user how to answer next time', () => {
    expect(approvalTimeoutReason(120_000)).toContain('node9 login');
  });

  // `connect` cannot be the advice: it needs a dashboard token, so a user who
  // is not in the dashboard cannot act on it.
  it('does not send the user to a command that needs a token first', () => {
    expect(approvalTimeoutReason(120_000)).not.toContain('node9 connect');
  });

  it('renders the configured timeout, not a hardcoded one', () => {
    expect(approvalTimeoutReason(30_000)).toContain('30s');
  });
});
