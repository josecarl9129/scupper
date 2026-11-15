All captures here are **synthetic until qualification**. They illustrate the
command-output fields described in DESIGN §14, and the pf/scutil/route command
formats; they are not captures from a qualified Mac or evidence of OS support.
The pf examples in tests/golden/mac are transcribed from DESIGN §14. OS build,
normalization transforms, sibling assessment, ND hop-limit handling, DHCP
eligibility and supervisor identity evidence in tests are synthetic inputs.
Real per-build captures and reviewed normalization goldens must replace/extend
these during V-05/V-20/V-21 qualification. No parser accepts arbitrary output by
falling back to an enabled/default/empty protected configuration.

Fix round 1 adds separate `main-nat.txt` (`-s nat`) and full-path recursive
`anchors.txt` (`pfctl -vv -s Anchors`) examples. Translation bypass cases use nat,
rdr and binat output in that separate observation, including anchors after ours;
they are not inserted into filter `-sr` fixtures. The recursive collector must
qualify the exact command, full-path/two-space indentation, recursive enumeration
of nested, translation-only and unreachable anchors, and top-level `_`-hidden
anchors on every build. `anchors-hidden.txt` is a separate synthetic example of
the latter; incomplete recursion remains a verification failure.

Fix round 2 removes the dummynet case from the `-s nat` tests. Dummynet is a
separate `pfctl -s dummynet` ruleset and is **not observed in 5a1**. Its coverage
and reinjection behavior remain an open qualification precondition, including
per-anchor reads; these filter/nat fixtures do not demonstrate its absence.
Selected uplink local-address and endpoint-route identity in tests are also
synthetic, independently supplied collector evidence until 5a2 qualification.

`interfaces.txt` models the reviewed macOS verbose PF format: a bare name means
no skip, and only ` (skip)` marks skip; `all` is an extra non-skipping kif.
The earlier invented attached/group/instance flags and `Token` in `-s info`
have been removed. Reference ownership comes from the acquire journal, with
`pfctl -s References` as a separate future collector observation.

`route-default.txt` models lookup through the default route, keeping the numeric
`route to` query separate from `destination: default` and `mask: default`.
Format references are Apple's published [route(8)](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.8)
and [route output implementation](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.c).
These references and the supplied PF review define synthetic fixture shapes,
not target-build captures or command-coverage qualification. Capture PF's own
man-page/output behavior, exact stock scrub/nat hooks and interface records
on the supported builds before 5a2 claims support.
