//! PQC Chat Client - Kyber Performance Testing Version
//!
//! Enhanced client that measures and reports detailed Kyber key exchange timings.

use anyhow::Result;
use clap::Parser;
use log::{error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use tokio_rustls::TlsConnector;

use pqc_chat::crypto::kyber::KyberKeyExchange;
use pqc_chat::protocol::SignalingMessage;

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(name = "pqc-kyber-test")]
#[command(about = "PQC Chat Kyber Performance Test Client")]
struct Args {
    /// Server hostname or IP
    #[arg(short, long, default_value = "127.0.0.1")]
    server: String,

    /// Server port
    #[arg(short, long, default_value = "8443")]
    port: u16,

    /// Username for connection
    #[arg(short, long, default_value = "kyber_test_user")]
    username: String,

    /// Number of connection attempts
    #[arg(short, long, default_value = "1")]
    attempts: u32,

    /// Delay between attempts (seconds)
    #[arg(short, long, default_value = "1")]
    delay: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// JSON output format
    #[arg(long)]
    json: bool,
}

/// Performance metrics for a single connection attempt
#[derive(Debug, serde::Serialize)]
struct ConnectionMetrics {
    attempt_number: u32,
    timestamp: String,
    tcp_connect_duration_ms: u64,
    tls_handshake_duration_ms: u64,
    kyber_keygen_duration_ms: u64,
    kyber_exchange_duration_ms: u64,
    login_duration_ms: u64,
    total_duration_ms: u64,
    success: bool,
    error: Option<String>,
}

/// Overall test results
#[derive(Debug, serde::Serialize)]
struct TestResults {
    server: String,
    port: u16,
    username: String,
    total_attempts: u32,
    successful_attempts: u32,
    success_rate: f64,
    metrics: Vec<ConnectionMetrics>,
    summary: TestSummary,
}

#[derive(Debug, serde::Serialize)]
struct TestSummary {
    avg_tcp_connect_ms: f64,
    avg_tls_handshake_ms: f64,
    avg_kyber_keygen_ms: f64,
    avg_kyber_exchange_ms: f64,
    avg_login_ms: f64,
    avg_total_duration_ms: f64,
    min_total_duration_ms: u64,
    max_total_duration_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    if !args.json {
        println!("🔐 PQC Chat Kyber Performance Test");
        println!("==================================");
        println!("Server: {}:{}", args.server, args.port);
        println!("Username: {}", args.username);
        println!("Attempts: {}", args.attempts);
        println!();
    }

    let mut test_results = TestResults {
        server: args.server.clone(),
        port: args.port,
        username: args.username.clone(),
        total_attempts: args.attempts,
        successful_attempts: 0,
        success_rate: 0.0,
        metrics: Vec::new(),
        summary: TestSummary {
            avg_tcp_connect_ms: 0.0,
            avg_tls_handshake_ms: 0.0,
            avg_kyber_keygen_ms: 0.0,
            avg_kyber_exchange_ms: 0.0,
            avg_login_ms: 0.0,
            avg_total_duration_ms: 0.0,
            min_total_duration_ms: u64::MAX,
            max_total_duration_ms: 0,
        },
    };

    // Run connection attempts
    for attempt in 1..=args.attempts {
        if !args.json && args.attempts > 1 {
            println!("🔄 Attempt {}/{}", attempt, args.attempts);
        }

        let metrics = perform_connection_test(&args.server, args.port, &args.username, attempt).await;
        
        if metrics.success {
            test_results.successful_attempts += 1;
        }

        if !args.json {
            print_metrics(&metrics, args.verbose);
        }

        test_results.metrics.push(metrics);

        // Delay between attempts
        if attempt < args.attempts && args.delay > 0 {
            tokio::time::sleep(Duration::from_secs(args.delay)).await;
        }
    }

    // Calculate summary statistics
    calculate_summary(&mut test_results);

    // Output results
    if args.json {
        println!("{}", serde_json::to_string_pretty(&test_results)?);
    } else {
        print_summary(&test_results);
    }

    Ok(())
}

async fn perform_connection_test(host: &str, port: u16, username: &str, attempt: u32) -> ConnectionMetrics {
    let mut metrics = ConnectionMetrics {
        attempt_number: attempt,
        timestamp: chrono::Utc::now().to_rfc3339(),
        tcp_connect_duration_ms: 0,
        tls_handshake_duration_ms: 0,
        kyber_keygen_duration_ms: 0,
        kyber_exchange_duration_ms: 0,
        login_duration_ms: 0,
        total_duration_ms: 0,
        success: false,
        error: None,
    };

    let total_start = Instant::now();

    // TCP Connection
    let tcp_start = Instant::now();
    let addr: SocketAddr = match format!("{}:{}", host, port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            metrics.error = Some(format!("Invalid address: {}", e));
            return metrics;
        }
    };

    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            metrics.tcp_connect_duration_ms = tcp_start.elapsed().as_millis() as u64;
            stream
        }
        Err(e) => {
            metrics.error = Some(format!("TCP connection failed: {}", e));
            return metrics;
        }
    };

    // TLS Handshake
    let tls_start = Instant::now();
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(e) => {
            metrics.error = Some(format!("Invalid server name: {}", e));
            return metrics;
        }
    };

    let mut tls_stream = match connector.connect(server_name, stream).await {
        Ok(stream) => {
            metrics.tls_handshake_duration_ms = tls_start.elapsed().as_millis() as u64;
            stream
        }
        Err(e) => {
            metrics.error = Some(format!("TLS handshake failed: {}", e));
            return metrics;
        }
    };

    // Kyber Key Generation
    let keygen_start = Instant::now();
    let kyber = KyberKeyExchange::new();
    metrics.kyber_keygen_duration_ms = keygen_start.elapsed().as_millis() as u64;

    // Kyber Key Exchange
    let exchange_start = Instant::now();
    let key_init = SignalingMessage::KeyExchangeInit {
        public_key: kyber.public_key_bytes(),
    };

    if let Err(e) = send_message(&mut tls_stream, &key_init).await {
        metrics.error = Some(format!("Failed to send key exchange init: {}", e));
        return metrics;
    }

    let response = match receive_message(&mut tls_stream).await {
        Ok(response) => response,
        Err(e) => {
            metrics.error = Some(format!("Failed to receive key exchange response: {}", e));
            return metrics;
        }
    };

    if let SignalingMessage::KeyExchangeResponse { ciphertext } = response {
        if let Err(e) = kyber.decapsulate(&ciphertext) {
            metrics.error = Some(format!("Kyber decapsulation failed: {}", e));
            return metrics;
        }
        metrics.kyber_exchange_duration_ms = exchange_start.elapsed().as_millis() as u64;
    } else {
        metrics.error = Some("Unexpected key exchange response".to_string());
        return metrics;
    }

    // Login
    let login_start = Instant::now();
    let login = SignalingMessage::Login {
        username: username.to_string(),
    };

    if let Err(e) = send_message(&mut tls_stream, &login).await {
        metrics.error = Some(format!("Failed to send login: {}", e));
        return metrics;
    }

    let response = match receive_message(&mut tls_stream).await {
        Ok(response) => response,
        Err(e) => {
            metrics.error = Some(format!("Failed to receive login response: {}", e));
            return metrics;
        }
    };

    if let SignalingMessage::LoginResponse { success, .. } = response {
        if success {
            metrics.login_duration_ms = login_start.elapsed().as_millis() as u64;
            metrics.success = true;
        } else {
            metrics.error = Some("Login failed".to_string());
            return metrics;
        }
    } else {
        metrics.error = Some("Unexpected login response".to_string());
        return metrics;
    }

    metrics.total_duration_ms = total_start.elapsed().as_millis() as u64;
    metrics
}

fn print_metrics(metrics: &ConnectionMetrics, verbose: bool) {
    if metrics.success {
        println!("✅ Attempt {} - SUCCESS ({} ms total)", metrics.attempt_number, metrics.total_duration_ms);
        if verbose {
            println!("   TCP Connect:     {} ms", metrics.tcp_connect_duration_ms);
            println!("   TLS Handshake:   {} ms", metrics.tls_handshake_duration_ms);
            println!("   Kyber KeyGen:    {} ms", metrics.kyber_keygen_duration_ms);
            println!("   Kyber Exchange:  {} ms", metrics.kyber_exchange_duration_ms);
            println!("   Login:           {} ms", metrics.login_duration_ms);
        }
    } else {
        println!("❌ Attempt {} - FAILED: {}", metrics.attempt_number, 
                 metrics.error.as_ref().unwrap_or(&"Unknown error".to_string()));
    }
    println!();
}

fn calculate_summary(results: &mut TestResults) {
    let successful_metrics: Vec<&ConnectionMetrics> = results.metrics.iter()
        .filter(|m| m.success)
        .collect();

    if successful_metrics.is_empty() {
        results.success_rate = 0.0;
        return;
    }

    results.success_rate = (results.successful_attempts as f64 / results.total_attempts as f64) * 100.0;

    let tcp_times: Vec<u64> = successful_metrics.iter().map(|m| m.tcp_connect_duration_ms).collect();
    let tls_times: Vec<u64> = successful_metrics.iter().map(|m| m.tls_handshake_duration_ms).collect();
    let keygen_times: Vec<u64> = successful_metrics.iter().map(|m| m.kyber_keygen_duration_ms).collect();
    let exchange_times: Vec<u64> = successful_metrics.iter().map(|m| m.kyber_exchange_duration_ms).collect();
    let login_times: Vec<u64> = successful_metrics.iter().map(|m| m.login_duration_ms).collect();
    let total_times: Vec<u64> = successful_metrics.iter().map(|m| m.total_duration_ms).collect();

    results.summary = TestSummary {
        avg_tcp_connect_ms: average(&tcp_times),
        avg_tls_handshake_ms: average(&tls_times),
        avg_kyber_keygen_ms: average(&keygen_times),
        avg_kyber_exchange_ms: average(&exchange_times),
        avg_login_ms: average(&login_times),
        avg_total_duration_ms: average(&total_times),
        min_total_duration_ms: *total_times.iter().min().unwrap_or(&0),
        max_total_duration_ms: *total_times.iter().max().unwrap_or(&0),
    };
}

fn average(values: &[u64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<u64>() as f64 / values.len() as f64
    }
}

fn print_summary(results: &TestResults) {
    println!("📊 TEST SUMMARY");
    println!("================");
    println!("Total Attempts:      {}", results.total_attempts);
    println!("Successful:          {}", results.successful_attempts);
    println!("Success Rate:        {:.1}%", results.success_rate);
    println!();
    
    if results.successful_attempts > 0 {
        println!("⏱️  TIMING AVERAGES (successful attempts only)");
        println!("================================================");
        println!("TCP Connect:         {:.1} ms", results.summary.avg_tcp_connect_ms);
        println!("TLS Handshake:       {:.1} ms", results.summary.avg_tls_handshake_ms);
        println!("Kyber Key Gen:       {:.1} ms", results.summary.avg_kyber_keygen_ms);
        println!("Kyber Exchange:      {:.1} ms", results.summary.avg_kyber_exchange_ms);
        println!("Login:               {:.1} ms", results.summary.avg_login_ms);
        println!("Total Average:       {:.1} ms", results.summary.avg_total_duration_ms);
        println!("Total Min:           {} ms", results.summary.min_total_duration_ms);
        println!("Total Max:           {} ms", results.summary.max_total_duration_ms);
    }
    
    println!();
    
    if results.successful_attempts != results.total_attempts {
        println!("❌ FAILURES");
        println!("===========");
        for metric in &results.metrics {
            if !metric.success {
                println!("Attempt {}: {}", metric.attempt_number, 
                         metric.error.as_ref().unwrap_or(&"Unknown error".to_string()));
            }
        }
    }
}

async fn send_message(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    message: &SignalingMessage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data = message.to_framed()?;
    stream.write_all(&data).await?;
    Ok(())
}

async fn receive_message(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<SignalingMessage, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;

    Ok(SignalingMessage::from_bytes(&msg_buf)?)
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}