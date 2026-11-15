/**
 * Fail closed on vendor redirects.
 *
 * The only outbound HTTP this server makes is the RocketCyber SDK's calls to the
 * RocketCyber API (@wyre-technology/node-rocketcyber, `executeRequest`), which
 * uses the global `fetch` and offers no option to set `redirect`. A default
 * `fetch` follows redirects, and the SDK sends the API key in a header, so a 3xx
 * from the vendor could carry that credential to another host. This wraps the
 * global `fetch` once so every call is made with `redirect: 'error'`: a 3xx
 * rejects the request instead of being followed.
 *
 * `redirect` is forced, not defaulted: nothing in this process has a reason to
 * follow a redirect. Installing twice is a no-op.
 */
const INSTALLED = Symbol.for('itsl.noRedirectFetch');

type FetchFn = typeof fetch;

export function installNoRedirectFetch(): void {
  const g = globalThis as unknown as { fetch: FetchFn & { [INSTALLED]?: true } };
  if (typeof g.fetch !== 'function' || g.fetch[INSTALLED]) return;
  const original = g.fetch.bind(globalThis) as FetchFn;
  const wrapped = ((input: Parameters<FetchFn>[0], init?: Parameters<FetchFn>[1]) =>
    original(input, { ...init, redirect: 'error' })) as FetchFn & { [INSTALLED]?: true };
  wrapped[INSTALLED] = true;
  g.fetch = wrapped;
}
