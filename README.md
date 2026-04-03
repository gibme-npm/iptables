# @gibme/iptables

A simple Node.js wrapper for managing iptables rules programmatically. Supports both IPv4 (`iptables`) and IPv6 (`ip6tables`), with built-in TTL-based expiration for host rules and automatic chain rebuilding.

## Requirements

- Linux with `iptables` / `ip6tables` installed
- Node.js >= 22
- Appropriate permissions to modify iptables rules (typically root)

## Installation

```bash
yarn add @gibme/iptables
```

or

```bash
npm install @gibme/iptables
```

## Documentation

[https://gibme-npm.github.io/iptables/](https://gibme-npm.github.io/iptables/)

## Usage

### Basic Example

```typescript
import IPTables from '@gibme/iptables';

const firewall = new IPTables({
    chain: 'INPUT'
});

// Add a host rule (default jump target: ACCEPT)
await firewall.add('192.168.1.100');

// Add a host rule with a specific jump target
await firewall.add('8.8.8.8', 'DROP');

// Add an interface rule
await firewall.addInterface('eth0', 'ACCEPT');

// Remove a host rule
await firewall.delete('8.8.8.8');

// Remove an interface rule
await firewall.deleteInterface('eth0');

// Flush the entire chain
await firewall.flush();
```

### IPv6 Support

```typescript
const firewall6 = new IPTables({
    chain: 'INPUT',
    family: 6
});

await firewall6.add('::1', 'ACCEPT');
```

### TTL-Based Expiration

Host rules are automatically removed after the configured TTL (default: 300 seconds). Use `keepAlive()` to reset the timer for a host.

```typescript
const firewall = new IPTables({
    chain: 'INPUT',
    stdTTL: 600 // rules expire after 10 minutes
});

await firewall.add('10.0.0.1', 'ACCEPT');

// Reset the expiration timer
await firewall.keepAlive('10.0.0.1');
```

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `chain` | `string` | *required* | The iptables chain to manage (e.g., `INPUT`, `FORWARD`, `OUTPUT`) |
| `stdTTL` | `number` | `300` | TTL in seconds for host rules (0 = no expiration) |
| `family` | `4 \| 6` | `4` | Address family — `4` for iptables, `6` for ip6tables |
| `iptables` | `string` | auto-detected | Path to the iptables binary |

### Events

The `IPTables` class extends `EventEmitter` and emits the following events:

- **`error`** — Emitted when an internal cache error occurs
- **`expired`** — Emitted when a host rule expires due to TTL

```typescript
firewall.on('error', (error) => {
    console.error('Firewall error:', error);
});

firewall.on('expired', (host) => {
    console.log(`Rule expired for: ${host}`);
});
```

## License

MIT
