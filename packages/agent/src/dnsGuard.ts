import * as dns from 'dns';
import { promisify } from 'util';

const lookupAsync = promisify(dns.lookup);

interface DnsCacheEntry {
  ips: string[];
  timestamp: number;
}

class DnsGuard {
  private cache = new Map<string, DnsCacheEntry>();
  // Enforce a strict TTL check (e.g. 10 seconds)
  private readonly CACHE_TTL = 10000;

  public async resolveAndLock(hostname: string): Promise<DnsCacheEntry> {
    try {
      // Use standard DNS resolution internally to pre-warm the lock
      // @ts-ignore
      const result = await lookupAsync(hostname, { all: true });
      const ips = Array.isArray(result) ? result.map(r => (r as any).address) : [(result as any).address];
      
      this.cache.set(hostname, {
        ips,
        timestamp: Date.now()
      });

      // Simple memory cleanup
      if (this.cache.size > 5000) {
        this.cache.clear();
      }

      return this.cache.get(hostname)!;
    } catch (e) {
      return { ips: [], timestamp: Date.now() };
    }
  }

  public trackCallbackResolution(hostname: string, address: string) {
      const existing = this.cache.get(hostname);
      if (existing) {
          if (!existing.ips.includes(address)) existing.ips.push(address);
          existing.timestamp = Date.now();
      } else {
          this.cache.set(hostname, { ips: [address], timestamp: Date.now() });
      }
  }

  public verify(hostname: string, ip: string): boolean {
    // If querying an explicitly IP-based string, skip hostname check
    if (this.isIp(hostname)) return true;

    const locked = this.cache.get(hostname);
    if (!locked) return true; // Fail-open if wasn't resolved through Node (e.g. native addons bypassing require-in-the-middle)

    const isExpired = Date.now() - locked.timestamp > this.CACHE_TTL;
    if (isExpired) return false;

    return locked.ips.includes(ip);
  }

  private isIp(str: string) {
    return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(str) || str.includes(':');
  }
}

export const dnsGuard = new DnsGuard();
