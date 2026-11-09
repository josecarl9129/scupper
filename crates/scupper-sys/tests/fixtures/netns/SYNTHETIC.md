# Synthetic forwarding fixtures

These four files were added by hand, not recorded on the named lab systems:

- `ubuntu-22.04/scupper-sysctl-net.ipv4.conf.default.forwarding.txt`
- `ubuntu-22.04/scupper-sysctl-net.ipv6.conf.default.forwarding.txt`
- `ubuntu-24.04/scupper-sysctl-net.ipv4.conf.default.forwarding.txt`
- `ubuntu-24.04/scupper-sysctl-net.ipv6.conf.default.forwarding.txt`

Their value, `1`, follows propagation from `all.forwarding=1` to the default
forwarding configuration. Treat them as synthetic until re-recorded by the lab
on the corresponding Ubuntu versions (V-03).
