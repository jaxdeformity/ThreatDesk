/**
 * Defang an IOC for human-readable display.
 *
 * Turns `http://evil.example.com/x` → `hxxp://evil[.]example[.]com/x`,
 * `1.2.3.4` → `1.2.3[.]4`, `attacker@evil.com` → `attacker[@]evil[.]com`.
 *
 * Rule: wrap every `.` with `[.]`, every `@` with `[@]`, and replace
 * `http://` / `https://` / `ftp://` scheme with `hxxp://` / `hxxps://` /
 * `fxp://`. Hashes, registry paths, and file paths are left unchanged
 * since they're not executable-by-paste.
 */
export function defang(value: string): string {
  if (!value) return value
  // Leave well-known hash formats alone (they're not "reachable")
  if (/^[0-9a-f]{32,128}$/i.test(value.trim())) return value
  // Leave raw registry paths alone
  if (value.startsWith('HKLM\\') || value.startsWith('HKCU\\')) return value

  let out = value
  out = out.replace(/\bhttps:\/\//gi, 'hxxps://')
  out = out.replace(/\bhttp:\/\//gi, 'hxxp://')
  out = out.replace(/\bftps:\/\//gi, 'fxps://')
  out = out.replace(/\bftp:\/\//gi, 'fxp://')
  out = out.replaceAll('.', '[.]')
  out = out.replaceAll('@', '[@]')
  return out
}

/** Convenience: defang every IOC value in a list of strings. */
export function defangAll(values: string[]): string[] {
  return values.map(defang)
}
