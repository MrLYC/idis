use crate::platform::BonjourHandle;
use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use tracing::warn;

const SERVICE_TELEMETRY: &str = "_MSM_Video_Control_Service._tcp.local.";
const SERVICE_DATA: &str = "_MSM_Video_Service._tcp.local.";

pub struct MdnsBonjourHandle {
    daemon: Option<ServiceDaemon>,
    fullnames: Vec<String>,
}

impl BonjourHandle for MdnsBonjourHandle {
    fn stop(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            for name in self.fullnames.drain(..) {
                let _ = daemon.unregister(&name);
            }
            let _ = daemon.shutdown();
        }
    }
}

impl Drop for MdnsBonjourHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Publish legacy display client Bonjour services (`_MSM_Video_Control_Service._tcp.` and
/// `_MSM_Video_Service._tcp.`) using pure-Rust mDNS-SD (used on Linux and Windows).
pub fn publish_mdns(
    service_name: &str,
    host_name: &str,
    telemetry_port: u16,
    data_port: u16,
) -> Result<Box<dyn BonjourHandle>> {
    let daemon = ServiceDaemon::new().context("failed to start mDNS-SD daemon")?;
    let clean_host = host_name
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .replace(' ', "-");
    let host_fqdn = if clean_host.is_empty() {
        "idis-host.local.".to_string()
    } else {
        format!("{clean_host}.local.")
    };

    let empty_props: [(&str, &str); 0] = [];
    let tel_info = ServiceInfo::new(
        SERVICE_TELEMETRY,
        service_name,
        &host_fqdn,
        "",
        telemetry_port,
        &empty_props[..],
    )
    .context("failed to construct telemetry mDNS ServiceInfo")?
    .enable_addr_auto();

    let data_info = ServiceInfo::new(
        SERVICE_DATA,
        service_name,
        &host_fqdn,
        "",
        data_port,
        &empty_props[..],
    )
    .context("failed to construct data mDNS ServiceInfo")?
    .enable_addr_auto();

    let mut fullnames = Vec::new();
    let tel_full = tel_info.get_fullname().to_string();
    let data_full = data_info.get_fullname().to_string();

    if let Err(e) = daemon.register(tel_info) {
        warn!("mDNS register telemetry failed: {e}");
    } else {
        fullnames.push(tel_full);
    }
    if let Err(e) = daemon.register(data_info) {
        warn!("mDNS register data failed: {e}");
    } else {
        fullnames.push(data_full);
    }

    Ok(Box::new(MdnsBonjourHandle {
        daemon: Some(daemon),
        fullnames,
    }))
}
