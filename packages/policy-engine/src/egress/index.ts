// @node9/policy-engine/egress — destination policy evaluation (GAP-5).
//
// Extraction (which host is a tool calling out to?) lives in ../shell
// (extractShellDestinations) because it needs the AST parser. This module is
// the pure POLICY layer: given the extracted destinations + the user's egress
// policy, decide allow / review / block. No I/O, no DNS — host reputation is
// out of scope; we only know what the config tells us.

import type { ShellDestination } from '../shell';
import { classifySsrf, normalizeIpLiteral, expandIpv6 } from './ssrf';

/**
 * A destination a tool call will reach, whichever carrier declared it: a
 * shell command (extractShellDestinations) or a tool argument
 * (extractToolDestinations). The interface is still spelled ShellDestination
 * where it lives (shell/index.ts, which is hashed by the extractor-version
 * gate, so a rename there is not free); this is the name that says what the
 * shape is for.
 */
export type Destination = ShellDestination;

export interface EgressPolicy {
  /** Master switch. Default false — opt-in, like dlp.pii. */
  enabled: boolean;
  /** Verdict for an UNKNOWN host (not in allow, not in deny, not private). */
  mode: 'off' | 'review' | 'block';
  /** Host globs always allowed (e.g. "*.github.com", "api.openai.com"). */
  allow: string[];
  /** Host globs always blocked — wins over allow/private. */
  deny: string[];
  /** Auto-allow localhost / RFC1918 / *.local. Default true. */
  allowPrivate: boolean;
  /** SSRF floor: exempts OVERRIDABLE tiers only (carrier-grade NAT, and
   *  loopback/RFC1918 when ssrfStrict is on). A tier-1 entry is ignored here
   *  and rejected at config load with a reason. */
  ssrfAllow?: readonly string[];
  /** SSRF floor tier 3: also block loopback and RFC1918. Off by default,
   *  because a developer talks to those constantly (72 of 308 destinations on
   *  measured real history). */
  ssrfStrict?: boolean;
}

export interface EgressVerdict {
  verdict: 'block' | 'review';
  host: string;
  binary: string;
  reason: string;
}

// Curated default allowlist of common dev / package / API hosts so turning
// egress on doesn't bury the user in prompts for routine traffic. "*.x" matches
// the apex (x) and any subdomain (see hostMatches). User `allow` adds to this.
export const DEFAULT_EGRESS_ALLOWLIST: readonly string[] = [
  // node9's own control plane (api, app, dev-api, staging and the apex).
  // Without it, turning egress on asks the user to approve node9 itself.
  // A user `deny` entry still wins over this list, see evaluateEgress.
  '*.node9.ai',
  '*.github.com',
  '*.githubusercontent.com',
  '*.npmjs.org',
  'pypi.org',
  '*.pythonhosted.org',
  'crates.io',
  '*.crates.io',
  'rubygems.org',
  'proxy.golang.org',
  'sum.golang.org',
  '*.anthropic.com',
  '*.openai.com',
  '*.googleapis.com',
  '*.docker.io',
  '*.docker.com',
  'deb.debian.org',
  '*.ubuntu.com',
];

/** Glob host match: "*" = any, "*.x" = apex x + any subdomain, else exact. */
export function hostMatches(host: string, pattern: string): boolean {
  const p = pattern.trim().toLowerCase();
  if (!p) return false;
  if (p === '*') return true;
  // BOTH sides fold. Canonicalizing only the host silently killed every list
  // entry stored in a non-canonical spelling: a `deny` written as `[::1]`
  // (the spelling the shell extractor hands over, so the obvious one to
  // copy) stopped matching and failed OPEN, and an `allow` written the same
  // way failed CLOSED. Entries arrive unnormalized from `node9 egress deny`,
  // a config.json edit and the managed list, so the fold belongs here, at
  // the one place both sides meet.
  const h = canonicalHost(host);
  if (p.startsWith('*.')) {
    const suffix = canonicalHost(p.slice(2));
    return h === suffix || h.endsWith('.' + suffix);
  }
  return h === canonicalHost(p);
}

function matchesAny(host: string, patterns: readonly string[] | undefined): boolean {
  // `?? []`: EgressPolicy.allow/deny are typed required, but PolicyConfig.egress
  // is optional for engine consumers that build a config by hand, and the new
  // tool branch reaches this before the ignored fast path. A partial
  // `{ enabled: true, mode: 'block' }` threw "patterns is not iterable" where
  // the parent returned allow.
  for (const p of patterns ?? []) if (hostMatches(host, p)) return true;
  return false;
}

/** Suffixes that name a private host by convention, not by address. */
const PRIVATE_HOST_SUFFIXES = ['.local', '.internal', '.localhost'] as const;

/**
 * Unique-local IPv6, fc00::/7. Lives here and not in ssrf.ts on purpose: the
 * floor decided ULA is not a tier (floor design H9, it is the RFC1918
 * analogue and RFC1918 is out of the floor), and that decision stands. For
 * allowPrivate the same analogy points the other way: RFC1918 IS private
 * here, so ULA is too.
 */
function isUniqueLocalV6(host: string): boolean {
  const ip = normalizeIpLiteral(host);
  if (!ip || !ip.includes(':')) return false;
  const g = expandIpv6(ip);
  return g !== null && (g[0] & 0xfe00) === 0xfc00;
}

/**
 * "Private" for the allowPrivate opt-in: loopback, RFC1918 and its IPv6
 * analogue, the unspecified address, and the conventional local suffixes.
 *
 * The address half is classifySsrf's answer, so every spelling that file
 * normalizes (brackets, zone id, IPv4-mapped IPv6) is one spelling here too.
 * The old body had its own IPv4-only regexes and returned false for `[::1]`,
 * which BLOCKED a local IPv6 dev server under allowPrivate (measured
 * 2026-09-20; the shell extractor keeps the brackets, the declared-URL
 * extractor strips them, and this function knew neither). Two parsers for
 * one question is how that happens.
 *
 * NOT private here: link-local, multicast, the metadata endpoints. Those are
 * the SSRF floor's tiers and allowPrivate must not be able to reach them;
 * evaluateEgress documents that the floor runs first, and this function
 * agrees with it rather than relying on it. CGNAT (100.64/10) is also out:
 * a mesh-VPN peer is not everyone's private network, which is why the floor
 * gave it its own tier; a Tailscale user lists the range in `allow`.
 */
export function isPrivateHost(host: string): boolean {
  // The trailing dot is stripped HERE rather than by the caller: this function
  // is exported and called on raw hosts elsewhere, and folding it upstream
  // only made the two callers disagree about `localhost.`.
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  // The floor's answer first. `metadata.google.internal` ends in `.internal`
  // and the old body called it private on the suffix alone; the floor blocks
  // it before this function is asked, but this function should not disagree.
  const m = classifySsrf(h);
  if (m) return m.kind === 'address' && (m.tier === 'private' || m.tier === 'unspecified');

  if (h === 'localhost') return true;
  if (PRIVATE_HOST_SUFFIXES.some((s) => h.endsWith(s))) return true;
  return isUniqueLocalV6(h);
}

/**
 * One spelling per address, for both a destination and a list entry.
 *
 * The two extractors spell one address two ways (measured 2026-09-20: the
 * shell extractor hands `[::1]` over with its brackets, hostOf strips them),
 * so without this an allow or deny entry matched one carrier and missed the
 * other on the same address. IP literals fold through normalizeIpLiteral
 * (brackets, zone id, IPv4-mapped IPv6 to the IPv4 it denotes); hostnames
 * lowercase and drop a trailing dot; a glob is left to hostMatches, which
 * folds the suffix only.
 *
 * Exported so the WRITE side (`normalizeEgressHost`, what `node9 egress
 * allow/deny` stores) folds the same way the READ side compares. A stored
 * entry and the key it is matched against must not be two functions.
 *
 * The egress verdict still reports the host AS WRITTEN, so the reason matches
 * what the user typed.
 */
export function canonicalHost(host: string): string {
  const ip = normalizeIpLiteral(host);
  return ip ?? host.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Evaluate extracted destinations against the egress policy. Precedence per
 * host: deny (block) > private-allow > allow/default-allow (skip) > unknown
 * (policy.mode). Returns the most severe actionable verdict across all
 * destinations — a deny or block-mode-unknown short-circuits; otherwise the
 * first review; null if everything is allowed (or policy disabled / mode off).
 * Pure.
 */
export function evaluateEgress(
  dests: readonly Destination[],
  policy: EgressPolicy
): EgressVerdict | null {
  if (!policy.enabled) return null;
  let review: EgressVerdict | null = null;

  for (const d of dests) {
    // The host is passed AS WRITTEN: hostMatches and isPrivateHost each fold
    // their own inputs, so there is no half-folded value in flight here.
    // Explicit deny always wins.
    if (matchesAny(d.host, policy.deny)) {
      return {
        verdict: 'block',
        host: d.host,
        binary: d.binary,
        reason: `Egress to ${d.host} is on the deny list.`,
      };
    }
    // Private / loopback: allowed when the operator opts in. This is NOT a
    // judgement that they are safe destinations. Link-local, multicast and the
    // cloud metadata endpoints are handled BEFORE this by the SSRF floor
    // (egress/ssrf.ts), which allowPrivate cannot reach.
    if (policy.allowPrivate && isPrivateHost(d.host)) continue;
    // Known-good (user allowlist or the curated defaults).
    if (matchesAny(d.host, policy.allow) || matchesAny(d.host, DEFAULT_EGRESS_ALLOWLIST)) continue;
    // Unknown destination.
    if (policy.mode === 'block') {
      return {
        verdict: 'block',
        host: d.host,
        binary: d.binary,
        reason: `Egress to unknown host ${d.host} is blocked (egress policy: block).`,
      };
    }
    if (policy.mode === 'review' && !review) {
      review = {
        verdict: 'review',
        host: d.host,
        binary: d.binary,
        reason: `${d.binary} is sending data to an unrecognized host (${d.host}). Approve this destination?`,
      };
    }
    // mode === 'off' → unknown hosts are not actioned.
  }

  return review;
}
