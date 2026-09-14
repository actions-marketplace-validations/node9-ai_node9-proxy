import { spawn } from 'child_process';

/**
 * Reject anything that is not a plain web URL before it reaches a child
 * process. The device-login flow hands us `verificationUrl` straight out of
 * the cloud's /device/start response, so this value is not ours: a hostile or
 * spoofed endpoint (including one reached via `node9 login --api-url ...`)
 * controls it completely.
 */
function isOpenableUrl(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  // A URL cannot legally contain control characters or whitespace; if one does,
  // something is trying to break out of the argument rather than open a page.
  // eslint-disable-next-line no-control-regex
  return !/[\x00-\x20\x7F"'`]/.test(url);
}

/**
 * Best-effort browser open — must never fail or block. On headless machines
 * (SSH, no display) the caller's printed URL is the fallback, so this returns
 * false and stays silent. Shared by `node9 signup` and the device-login flow.
 */
export function openBrowser(url: string): boolean {
  if (!isOpenableUrl(url)) return false;
  // Headless heuristics: no display server on Linux, or an SSH session
  // anywhere — opening would either fail or open on the wrong machine.
  if (process.env.SSH_CONNECTION || process.env.SSH_TTY) return false;
  if (process.platform === 'linux' && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) {
    return false;
  }
  // Never route the URL through a command interpreter.
  //
  // The original code used spawn('start', [url], { shell: true }), where Node
  // concatenates args into one shell string without escaping them (Node's own
  // DEP0190), so `&` in a URL ran whatever followed. Dropping `shell: true`
  // and calling cmd.exe directly is NOT enough, which a real Windows box
  // settled: Node only quotes an argument that contains a space, tab or quote,
  // a URL has none, so cmd.exe still re-parsed the unquoted `&`.
  //
  //   node -e "spawn('cmd.exe',['/c','echo','https://x.test/?a=1&ver'])"
  //   -> https://x.test/?a=1
  //      Microsoft Windows [Version 10.0.26200.9445]
  //
  // `start` is a cmd builtin, so using it means using cmd. explorer.exe is a
  // real executable that hands the URL to the default handler, so there is no
  // interpreter in the path and `&` is just a character. Escaping for cmd was
  // the alternative and it is the kind of thing that is wrong until proven
  // otherwise; this removes the class instead.
  const [cmd, args] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['explorer.exe', [url]]
        : ['xdg-open', [url]];
  try {
    const child = spawn(cmd, args as string[], {
      stdio: 'ignore',
      detached: true,
    });
    child.on('error', () => {
      /* no browser available — the printed URL is the fallback */
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}
