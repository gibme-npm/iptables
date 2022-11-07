# Simple IPTables helper/wrapper

```typescript
import IPTables from '@gibme/iptables';

(async() => {
    const firewall = new IPTables({
        chain: 'INPUT' // dangerous during flush
    });
    
    await firewall.add('8.8.8.8', 'DROP');
    
    await firewall.addInterface('eth2', 'DROP');
    
    await firewall.delete('8.8.8.8');
    
    await firewall.deleteInterface('eth2');
})();
```
