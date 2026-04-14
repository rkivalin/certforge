use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::op::{Message, MessageType, OpCode, MessageFinalizer, Query, ResponseCode, UpdateMessage};
use hickory_proto::rr::rdata::{TLSA, TXT};
use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::xfer::{DnsHandle, DnsResponse};
use tokio::task::JoinHandle;

use hickory_client::{ClientError, ClientErrorKind};
use hickory_proto::ProtoErrorKind;

use crate::config::{DnsProtocol, DnsClientConfig};
use crate::dns::tlsa::TlsaRecord;
use crate::error::{Error, Result};

/// Produce a clear error message from a hickory ClientError.
fn dns_err(operation: &str, e: ClientError) -> Error {
    let detail = match e.kind() {
        ClientErrorKind::Proto(proto) => match proto.kind() {
            ProtoErrorKind::Busy => "server busy".into(),
            ProtoErrorKind::Timeout => "request timed out".into(),
            ProtoErrorKind::RequestRefused => {
                "update REFUSED by server (check TSIG key and update policy)".into()
            }
            ProtoErrorKind::NoRecordsFound { response_code, .. } => {
                format!("server responded with {response_code}")
            }
            _ => format!("{proto}"),
        },
        _ => format!("{e}"),
    };
    Error::DnsUpdate(format!("{operation}: {detail}"))
}

fn dns_proto_err(operation: &str, e: hickory_proto::ProtoError) -> Error {
    dns_err(operation, ClientError::from(e))
}

/// Check the DNS response code from an update operation.
/// Hickory doesn't check response codes for updates, so we must do it ourselves.
fn check_update_response(operation: &str, response: &DnsResponse) -> Result<()> {
    let code = response.response_code();
    match code {
        ResponseCode::NoError => Ok(()),
        ResponseCode::Refused => Err(Error::DnsUpdate(format!(
            "{operation}: update REFUSED by server (check TSIG key name, secret, and update-policy/allow-update in zone config)"
        ))),
        ResponseCode::NotAuth => Err(Error::DnsUpdate(format!(
            "{operation}: server is not authoritative for this zone (NOTAUTH)"
        ))),
        ResponseCode::NXRRSet => Err(Error::DnsUpdate(format!(
            "{operation}: prerequisite failed - RRset does not exist (NXRRSET)"
        ))),
        ResponseCode::YXRRSet => Err(Error::DnsUpdate(format!(
            "{operation}: prerequisite failed - RRset already exists (YXRRSET)"
        ))),
        ResponseCode::NotZone => Err(Error::DnsUpdate(format!(
            "{operation}: update name is not within the zone (NOTZONE)"
        ))),
        _ => Err(Error::DnsUpdate(format!(
            "{operation}: server responded with {code}"
        ))),
    }
}

/// DNS update client for RFC 2136 operations.
pub struct DnsUpdater {
    client: Client,
    _bg: JoinHandle<()>,
}

impl DnsUpdater {
    /// Connect to a DNS server with TSIG authentication.
    pub async fn connect(
        config: &DnsClientConfig,
        signer: Arc<dyn MessageFinalizer>,
    ) -> Result<Self> {
        let addr_str = format!("{}:{}", config.server, config.port);
        let addr: SocketAddr = addr_str
            .to_socket_addrs()
            .map_err(|e| Error::DnsUpdate(format!("failed to resolve DNS server {addr_str}: {e}")))?
            .next()
            .ok_or_else(|| Error::DnsUpdate(format!("DNS server {addr_str} resolved to no addresses")))?;

        tracing::debug!(%addr, server = %config.server, "resolved DNS server address");
        let timeout = Duration::from_secs(10);

        match config.protocol {
            DnsProtocol::Tcp => Self::connect_tcp(addr, signer, timeout).await,
            DnsProtocol::Udp => {
                tracing::warn!("UDP requested but using TCP for DNS updates (RFC 2136 recommendation)");
                Self::connect_tcp(addr, signer, timeout).await
            }
        }
    }

    async fn connect_tcp(
        addr: SocketAddr,
        signer: Arc<dyn MessageFinalizer>,
        timeout: Duration,
    ) -> Result<Self> {
        let (stream, sender) = TcpClientStream::new::<hickory_proto::runtime::TokioRuntimeProvider>(
            addr, None, Some(timeout), Default::default(),
        );

        let (client, bg) = Client::with_timeout(
            stream,
            sender,
            timeout,
            Some(signer),
        )
        .await
        .map_err(|e| dns_proto_err("TCP connection failed", e))?;

        let bg_handle = tokio::spawn(async move {
            let _ = bg.await;
        });

        Ok(Self {
            client,
            _bg: bg_handle,
        })
    }

    /// Add a TXT record (for ACME DNS-01 challenge).
    ///
    /// Uses `append` (not `create`) so it succeeds even if a stale record
    /// from a previous failed run is still present.
    pub async fn add_txt_record(
        &mut self,
        zone: &Name,
        name: &Name,
        value: &str,
        ttl: u32,
    ) -> Result<()> {
        let txt = TXT::new(vec![value.to_string()]);
        let record = Record::from_rdata(name.clone(), ttl, RData::TXT(txt));

        let response = self
            .client
            .append(record, zone.clone(), false)
            .await
            .map_err(|e| dns_err("failed to add TXT record", e))?;
        check_update_response("failed to add TXT record", &response)?;

        tracing::debug!(%name, %value, "added TXT record");
        Ok(())
    }

    /// Delete a specific TXT record (cleanup after ACME challenge).
    pub async fn delete_txt_record(
        &mut self,
        zone: &Name,
        name: &Name,
        value: &str,
    ) -> Result<()> {
        let txt = TXT::new(vec![value.to_string()]);
        let record = Record::from_rdata(name.clone(), 0, RData::TXT(txt));

        let response = self
            .client
            .delete_by_rdata(record, zone.clone())
            .await
            .map_err(|e| dns_err("failed to delete TXT record", e))?;
        check_update_response("failed to delete TXT record", &response)?;

        tracing::debug!(%name, "deleted TXT record");
        Ok(())
    }

    /// Add a TLSA record (for DANE pre-publication or initial publish).
    pub async fn add_tlsa_record(
        &mut self,
        zone: &Name,
        name: &Name,
        tlsa: &TlsaRecord,
        ttl: u32,
    ) -> Result<()> {
        let rdata = tlsa_to_rdata(tlsa);
        let record = Record::from_rdata(name.clone(), ttl, rdata);

        let response = self
            .client
            .create(record, zone.clone())
            .await
            .map_err(|e| dns_err("failed to add TLSA record", e))?;
        check_update_response("failed to add TLSA record", &response)?;

        tracing::debug!(%name, rdata = %tlsa.to_rdata_string(), "added TLSA record");
        Ok(())
    }

    /// Replace all TLSA records at a name atomically (single RFC 2136 update).
    pub async fn replace_tlsa_records(
        &mut self,
        zone: &Name,
        name: &Name,
        records: &[TlsaRecord],
        ttl: u32,
    ) -> Result<()> {
        let mut message = Message::new();
        message
            .set_id(0)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);

        let mut zone_query = Query::new();
        zone_query
            .set_name(zone.clone())
            .set_query_class(DNSClass::IN)
            .set_query_type(RecordType::SOA);
        message.add_zone(zone_query);

        // Delete all existing TLSA records at this name
        let mut delete = Record::update0(name.clone(), 0, RecordType::TLSA);
        delete.set_dns_class(DNSClass::ANY);
        message.add_update(delete);

        // Add new records in the same update
        for tlsa in records {
            let rdata = tlsa_to_rdata(tlsa);
            message.add_update(Record::from_rdata(name.clone(), ttl, rdata));
        }

        use std::pin::Pin;
        use futures_core::Stream;
        let mut stream = self.client.send(message);
        let response = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))
            .await
            .ok_or_else(|| Error::DnsUpdate("replace TLSA records: no response".into()))?
            .map_err(|e| dns_err("failed to replace TLSA records", ClientError::from(e)))?;
        check_update_response("failed to replace TLSA records", &response)?;

        tracing::debug!(%name, count = records.len(), "replaced TLSA records");
        Ok(())
    }

    /// Query TLSA records at a given name.
    pub async fn query_tlsa(&mut self, name: &Name) -> Result<Vec<TlsaRecord>> {
        let response = self
            .client
            .query(name.clone(), hickory_proto::rr::DNSClass::IN, RecordType::TLSA)
            .await
            .map_err(|e| dns_err("TLSA query failed", e))?;

        let mut records = Vec::new();
        for record in response.answers() {
            if let RData::TLSA(tlsa) = record.data() {
                records.push(TlsaRecord {
                    usage: tlsa.cert_usage().into(),
                    selector: tlsa.selector().into(),
                    matching_type: tlsa.matching().into(),
                    association_data: tlsa.cert_data().to_vec(),
                });
            }
        }

        Ok(records)
    }

    /// Delete a specific TLSA record.
    #[allow(dead_code)]
    pub async fn delete_tlsa_record(
        &mut self,
        zone: &Name,
        name: &Name,
        tlsa: &TlsaRecord,
    ) -> Result<()> {
        let rdata = tlsa_to_rdata(tlsa);
        let record = Record::from_rdata(name.clone(), 0, rdata);

        let response = self
            .client
            .delete_by_rdata(record, zone.clone())
            .await
            .map_err(|e| dns_err("failed to delete TLSA record", e))?;
        check_update_response("failed to delete TLSA record", &response)?;

        tracing::debug!(%name, rdata = %tlsa.to_rdata_string(), "deleted TLSA record");
        Ok(())
    }

}

/// Convert our TlsaRecord to hickory RData.
fn tlsa_to_rdata(tlsa: &TlsaRecord) -> RData {
    let cert_usage = match tlsa.usage {
        0 => CertUsage::PkixTa,
        1 => CertUsage::PkixEe,
        2 => CertUsage::DaneTa,
        3 => CertUsage::DaneEe,
        n => CertUsage::Unassigned(n),
    };
    let selector = match tlsa.selector {
        0 => Selector::Full,
        1 => Selector::Spki,
        n => Selector::Unassigned(n),
    };
    let matching = match tlsa.matching_type {
        0 => Matching::Raw,
        1 => Matching::Sha256,
        2 => Matching::Sha512,
        n => Matching::Unassigned(n),
    };

    RData::TLSA(TLSA::new(
        cert_usage,
        selector,
        matching,
        tlsa.association_data.clone(),
    ))
}
