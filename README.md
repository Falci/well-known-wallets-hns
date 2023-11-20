# Well-Known Wallets Client for Handshake domains

[HIP2](https://hsd-dev.org/HIPs/proposals/0002/)

### Usage

```js
import { init, getAddress } from 'well-known-wallets-hns';

init('192.168.1.55'); // HSD node

getAddress('mydomain.hns')
  .then((addr) => console.log(addr))
  .catch((err) => console.log(err));
```
