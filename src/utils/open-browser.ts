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
  // Measured on Windows 10.0.26200, three candidates, one run:
  //   rundll32.exe url.dll,FileProtocolHandler <url>   opened the browser, &b=2 intact
  //   cmd.exe /c start "" "<url>"  (quoted)            opened the browser, &b=2 intact
  //   powershell.exe -Command Start-Process '<url>'    opened nothing
  //
  // Two worked; this takes rundll32 because it is the only one with no command
  // interpreter in the path. The cmd form is safe only while its quoting stays
  // exactly right, and that is precisely what went wrong twice already:
  // spawn('start', [url], { shell: true }) concatenated unescaped (Node's own
  // DEP0190), and dropping the shell option did not help either, because Node
  // leaves a space-free argument unquoted and cmd.exe parsed the `&` it was
  // handed. With rundll32 there is nothing to quote and nothing to get wrong.
  //
  // explorer.exe was tried and rejected: its argument parsing is quirky enough
  // that it opened a folder window instead of the browser.
  //
  // The isOpenableUrl scheme check above is load-bearing here, not decoration:
  // FileProtocolHandler will happily open file:// too.
  const [cmd, args] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['rundll32.exe', ['url.dll,FileProtocolHandler', url]]
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
