//! M2 host units. Installation is a separate administrative operation.

/// Boot the data path; only system shutdown stops clients, preserving containment.
#[must_use]
pub const fn scupper_net() -> &'static str {
    "# scupper-net.service\n# Stop preserves protection; clean-stop tears down clients only during system shutdown.\n[Unit]\nDescription=scupper data-path namespace\nDefaultDependencies=no\nAfter=local-fs.target systemd-modules-load.service\nBefore=network-pre.target scupperd.service shutdown.target\nConflicts=shutdown.target\nWants=network-pre.target\n[Service]\nType=oneshot\nTimeoutStartSec=90\nTimeoutStopSec=30s\nRemainAfterExit=yes\nExecStart=/usr/local/bin/scupper boot\nExecStop=/usr/local/bin/scupper boot --clean-stop\n[Install]\nWantedBy=multi-user.target\n"
}

/// Run the single writer in the host mount and network namespaces.
#[must_use]
pub const fn scupperd() -> &'static str {
    "# scupperd.service\n[Unit]\nDescription=scupper reconciler\nWants=scupper-net.service network-online.target\nAfter=scupper-net.service network-online.target\nStartLimitIntervalSec=0\n[Service]\nType=notify\nWatchdogSec=30\nRestart=always\nRestartSec=2s\nTimeoutStartSec=90\nLimitCORE=0\n# Keep the host mount namespace: restore_mount needs /run/netns propagation.\nExecStart=/usr/local/bin/scupperd\n[Install]\nWantedBy=multi-user.target\n"
}

#[cfg(test)]
mod tests {
    #[test]
    fn m2_goldens() {
        assert_eq!(
            super::scupper_net(),
            include_str!("../../../../tests/golden/units/scupper-net.service")
        );
        assert_eq!(
            super::scupperd(),
            include_str!("../../../../tests/golden/units/scupperd.service")
        );
    }
}
