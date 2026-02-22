/**
 * Compute exponential backoff delay with optional jitter.
 * @param attempt 0-indexed attempt number
 * @param baseMs Base delay in ms (default 1000)
 * @param maxMs Max delay cap in ms (default 60000)
 * @returns Delay in ms
 */
export function backoffDelay(
  attempt: number,
  baseMs = 1_000,
  maxMs = 60_000
): number {
  const exp = Math.min(attempt, 10); // cap exponent to avoid overflow
  const delay = baseMs * Math.pow(2, exp);
  // Add ±10% jitter to prevent thundering herd
  const jitter = delay * 0.1 * (Math.random() * 2 - 1);
  return Math.min(Math.round(delay + jitter), maxMs);
}

/** Sleep for the given number of milliseconds */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
