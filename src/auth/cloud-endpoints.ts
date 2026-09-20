// One resolver for cloud API endpoints outside the /intercept namespace.
// Precedence: explicit override → NODE9_API_URL (the intercept base, so a dev
// pointing the daemon at staging reaches the same host) → prod default.
//
// Pinned, like every other apiUrl seam (auth/api-url): the endpoints resolved
// here are `node9 login` and `node9 connect`, which carry no device key, but
// they are where the key is MINTED. An attacker-controlled NODE9_API_URL (a
// hook inherits the agent's env, and sandbox/config.ts already lists the
// variable as forbidden for that reason) would have the attacker's host issue
// the key, which is then stored against the real DEFAULT_API_URL, so the
// machine silently joins the attacker's workspace through node9's own host.
//
// A rejected value THROWS rather than falling back to prod: the user typed
// `--api-url` or exported the variable on purpose, and logging in to the
// wrong workspace without a word is worse than an error naming the fix.
import { validateApiUrl, HOST_ALLOW_ENV } from './api-url';

const PROD_BASE = 'https://api.node9.ai/api/v1';

export function resolveCloudEndpoint(pathSuffix: string, override?: string): string {
  const raw = override || process.env.NODE9_API_URL;
  if (!raw) return PROD_BASE + pathSuffix;
  if (!validateApiUrl(raw)) {
    throw new Error(
      `${override ? '--api-url' : 'NODE9_API_URL'} "${raw.slice(0, 200)}" is not an allowed node9 host. ` +
        `For a self-hosted control plane set ${HOST_ALLOW_ENV}=<your-domain>.`
    );
  }
  if (override) return override;
  return raw.replace(/\/intercept\/?$/, '') + pathSuffix;
}
