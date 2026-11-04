use crate::config::Config;

/// Laptop-owned listeners are checked locally. Every VM-owned channel is
/// checked at that VM, never using first-success fallback through another VM.
pub(super) fn report(cfg: &Config, channel_port: u16, files_port: u16) -> bool {
    let peers = match cfg.peer_ips() {
        Ok(peers) => peers,
        Err(error) => {
            super::print_line(format_args!("peers: FAIL — {error}"));
            return false;
        }
    };
    let local = vec![cfg.listen.clone()];
    let url = super::channel(
        cfg,
        &local,
        "url channel",
        channel_port,
        super::probe_url_channel,
    );
    let relay = super::browser::report(cfg);
    super::grant::report();
    let pcsc = super::optional_channel(cfg, &local, "pcsc channel", "pcsc_port", cfg.pcsc_port);
    let pulse = super::optional_channel(cfg, &local, "pulse channel", "pulse_port", cfg.pulse_port);
    let mut healthy = url && relay && pcsc && pulse;
    for peer in peers {
        let host = vec![peer.to_string()];
        let preview = super::channel(
            cfg,
            &host,
            &format!("peer {peer} file preview"),
            files_port,
            super::probe_file_preview,
        );
        let bridge = super::channel(
            cfg,
            &host,
            &format!("peer {peer} callback bridge"),
            cfg.bridge_port,
            super::probe_bridge,
        );
        let feed = super::optional_channel(
            cfg,
            &host,
            &format!("peer {peer} browser feed"),
            "grant_port",
            cfg.grant_port,
        );
        healthy &= preview && bridge && feed;
    }
    healthy
}
