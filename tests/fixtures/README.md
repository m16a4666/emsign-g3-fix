# Public certificate fixtures

The `.crt` files contain public root certificates only, with no private keys.
They were extracted unchanged from [certifi 2024.08.30](https://github.com/certifi/python-certifi/blob/325c2fde4f8eec10d682b09f3b0414dc05e69a81/certifi/cacert.pem).
`unrelated.crt` is the first unrelated root in that bundle and ensures tests keep a nonempty trust store.

These roots are test data, including certificates deliberately removed from trust.
Never install them on a real system. Only `integration.py` installs them, in an explicitly marked disposable Docker container.

Certificate SHA-256:

| Fixture | SHA-256 |
| --- | --- |
| G1 | `40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367` |
| C1 | `125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f` |
| C3 | `bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3` |

G3 and AAA are identified by SPKI SHA-256 from the [Mozilla incident notice](https://www.openwall.com/lists/oss-security/2026/10/20/1).
The TLS-G3 SPKI is included in the implementation from that notice; a TLS-G3 certificate is not present in this historical certifi bundle.
