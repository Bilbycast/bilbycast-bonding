//! `bilbycast-bonder` — dedicated packet-bonding appliance.
//!
//! Small binary (no libavcodec, no fdk-aac, no HTTP server) that
//! reads a UDP input, frames each datagram into the bond protocol,
//! and transmits across N paths to a matching receiver-mode bonder
//! which reassembles and writes UDP out. Intended for deployment on
//! edge-router hardware — cellular gateways, field trucks, remote
//! contribution boxes.
//!
//! Invocation:
//!
//! ```sh
//! bilbycast-bonder --config /etc/bilbycast-bonder.json
//! ```

mod config;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::signal;

use bonding_transport::{
    BondSocket, PacketHints, RoundRobinScheduler, WeightedRttScheduler,
};

use config::{BonderConfig, BonderRole, IoEndpoint, SchedulerKind};

#[derive(Parser, Debug)]
#[command(
    name = "bilbycast-bonder",
    version,
    about = "Dedicated bonding appliance built on bilbycast-bonding"
)]
struct Cli {
    /// Path to the JSON config.
    #[arg(short, long)]
    config: String,

    /// Log level — overrides RUST_LOG.
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(cli.log.clone()))
        .init();

    let raw = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("read config {}", cli.config))?;
    let cfg: BonderConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parse config {}", cli.config))?;

    log::info!(
        "bilbycast-bonder starting: role={:?}, flow_id={}, {} path(s)",
        cfg.role,
        cfg.flow_id,
        cfg.paths.len()
    );

    match cfg.role {
        BonderRole::Sender => run_sender(cfg).await,
        BonderRole::Receiver => run_receiver(cfg).await,
    }
}

async fn run_sender(cfg: BonderConfig) -> anyhow::Result<()> {
    let input = cfg
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("sender role requires `input`"))?;
    let bind = match input {
        IoEndpoint::Udp { bind: Some(b), .. } => *b,
        _ => return Err(anyhow!("sender UDP input requires `bind`")),
    };
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind UDP input {bind}"))?;
    log::info!("UDP ingress bound: {}", bind);

    let bsock_cfg = cfg.to_socket_config()?;
    let path_ids: Vec<u8> = bsock_cfg.paths.iter().map(|p| p.id).collect();
    let bond: BondSocket = match cfg.scheduler {
        SchedulerKind::WeightedRtt => {
            BondSocket::sender(bsock_cfg, WeightedRttScheduler::new(path_ids))
                .await
                .map_err(|e| anyhow!("bond sender setup: {e}"))?
        }
        SchedulerKind::RoundRobin => {
            BondSocket::sender(bsock_cfg, RoundRobinScheduler::new(path_ids))
                .await
                .map_err(|e| anyhow!("bond sender setup: {e}"))?
        }
    };

    log::info!("bond sender up on {} paths", cfg.paths.len());

    let bond = Arc::new(bond);
    let stats_bond = bond.clone();
    tokio::spawn(stats_loop(stats_bond, cfg.paths.iter().map(|p| p.id).collect()));

    let mut buf = vec![0u8; 2048];
    let ingress_fut = async {
        loop {
            let (len, _from) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("UDP recv error: {e}");
                    continue;
                }
            };
            let payload = Bytes::copy_from_slice(&buf[..len]);
            if let Err(e) = bond.send(payload, PacketHints::default()).await {
                log::warn!("bond send error: {e}");
            }
        }
    };

    tokio::select! {
        _ = ingress_fut => Ok(()),
        _ = signal::ctrl_c() => {
            log::info!("ctrl-c — shutting down");
            Ok(())
        }
    }
}

async fn run_receiver(cfg: BonderConfig) -> anyhow::Result<()> {
    let output = cfg
        .output
        .as_ref()
        .ok_or_else(|| anyhow!("receiver role requires `output`"))?;
    let dest: SocketAddr = match output {
        IoEndpoint::Udp { dest: Some(d), .. } => *d,
        _ => return Err(anyhow!("receiver UDP output requires `dest`")),
    };
    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let out_socket = UdpSocket::bind(bind).await?;
    out_socket
        .connect(dest)
        .await
        .with_context(|| format!("connect UDP output {dest}"))?;
    log::info!("UDP egress -> {}", dest);

    let bsock_cfg = cfg.to_socket_config()?;
    let path_ids: Vec<u8> = bsock_cfg.paths.iter().map(|p| p.id).collect();
    let bond = BondSocket::receiver(bsock_cfg)
        .await
        .map_err(|e| anyhow!("bond receiver setup: {e}"))?;

    log::info!("bond receiver up on {} paths", cfg.paths.len());

    let bond = Arc::new(bond);
    let stats_bond = bond.clone();
    tokio::spawn(stats_loop(stats_bond, path_ids.clone()));

    let recv_fut = async {
        loop {
            match bond.recv().await {
                Some(payload) => {
                    if let Err(e) = out_socket.send(&payload).await {
                        log::warn!("UDP egress send error: {e}");
                    }
                }
                None => {
                    log::info!("bond receiver closed");
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = recv_fut => Ok(()),
        _ = signal::ctrl_c() => {
            log::info!("ctrl-c — shutting down");
            Ok(())
        }
    }
}

async fn stats_loop(bond: Arc<BondSocket>, path_ids: Vec<u8>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let s = bond.stats().snapshot();
        log::info!(
            "bond stats: sent={} bytes={} retx={} recv={} delivered={} gaps_recovered={} gaps_lost={}",
            s.packets_sent,
            s.bytes_sent,
            s.packets_retransmitted,
            s.packets_received,
            s.packets_delivered,
            s.gaps_recovered,
            s.gaps_lost
        );
        for id in &path_ids {
            if let Some(ps) = bond.path_stats(*id) {
                let p = ps.snapshot();
                log::info!(
                    "  path[{}]: sent={} recv={} rtt={:.1}ms loss={:.2}% nacks_rx={} retx_tx={} dead={}",
                    id,
                    p.packets_sent,
                    p.packets_received,
                    p.rtt_ms(),
                    p.loss_fraction() * 100.0,
                    p.nacks_received,
                    p.retransmits_sent,
                    p.dead
                );
            }
        }
    }
}
