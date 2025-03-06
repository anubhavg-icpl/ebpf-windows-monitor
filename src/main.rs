// src/main.rs
use aya::{include_bytes_aligned, Bpf, BpfLoader};
use aya::maps::RingBuffer;
use aya::programs::{TracePoint, ProgramError};
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{info, warn, error};
use std::{convert::TryFrom, sync::Arc};
use tokio::signal;
use windows::Win32::NetworkManagement::IpHelper;
use windows::Win32::System::Threading;
use windows::Win32::Foundation::HANDLE;

// This structure must match the C structure in the eBPF program
#[repr(C)]
struct Event {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    
    // Load the eBPF program
    info!("Loading eBPF program");
    
    // Check if running in WSL or Windows, as the approach differs
    let is_wsl = std::path::Path::new("/proc/sys/kernel").exists();
    
    if !is_wsl {
        info!("Running on Windows - ensuring eBPF runtime is available");
        // For Windows native mode, need to check if the eBPF runtime is available
        // This assumes the WinBPF/eBPFKit from Microsoft is installed
        // Alternatively, you might need to invoke WSL
    }
    
    // The #[rustfmt::skip] is used to prevent rustfmt from breaking the include! macro
    #[rustfmt::skip]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(
            "../target/bpfel-unknown-none/release/ebpf-program"
        ))?;
    
    // Attach the eBPF programs to tracepoints
    info!("Attaching eBPF programs");
    let program_socket: &mut TracePoint = bpf.program_mut("trace_inet_sock_set_state")
        .unwrap()
        .try_into()?;
    program_socket.load()?;
    program_socket.attach("sock", "inet_sock_set_state")?;
    
    let program_process: &mut TracePoint = bpf.program_mut("trace_process_exec")
        .unwrap()
        .try_into()?;
    program_process.load()?;
    program_process.attach("sched", "sched_process_exec")?;
    
    // Create a channel to receive events in userspace
    info!("Setting up event processing pipeline");
    let mut events = RingBuffer::try_from(bpf.map_mut("events")?)?;
    
    // Store for security context information - useful for correlation
    let security_context = Arc::new(SecurityContext::new());
    let ctx_clone = security_context.clone();
    
    // Process events as they arrive
    let cpus = online_cpus()?;
    for cpu in cpus {
        events.consume(
            cpu,
            |data: &[u8]| {
                let event = parse_event(data);
                process_event(&event, &ctx_clone);
                Ok(0)
            }
        )?;
    }
    
    // Keep the program running until Ctrl+C is pressed
    info!("Security monitor running. Press Ctrl+C to exit.");
    signal::ctrl_c().await?;
    info!("Exiting");
    
    Ok(())
}

// Parse the raw bytes into an Event structure
fn parse_event(data: &[u8]) -> Event {
    let mut event = Event {
        pid: 0,
        uid: 0,
        comm: [0; 16],
        dst_ip: 0,
        dst_port: 0,
        protocol: 0,
    };
    
    unsafe {
        std::ptr::copy_nonoverlapping(
            data.as_ptr(),
            &mut event as *mut Event as *mut u8,
            std::mem::size_of::<Event>(),
        );
    }
    
    event
}

// Process and analyze the event
fn process_event(event: &Event, ctx: &Arc<SecurityContext>) {
    let comm = std::str::from_utf8(&event.comm)
        .unwrap_or("unknown")
        .trim_end_matches(char::from(0));
    
    if event.dst_ip == 0 && event.dst_port == 0 {
        // Process creation event
        info!(
            "Process started: PID={}, UID={}, Command={}",
            event.pid, event.uid, comm
        );
        
        // Apply security rules for new processes
        if let Some(threat_level) = ctx.check_process_threat(event.pid, comm) {
            if threat_level > 5 {
                warn!("Suspicious process detected: {} (threat level: {})", comm, threat_level);
                // You could implement additional actions here:
                // - Log to SIEM
                // - Quarantine process
                // - Alert security team
            }
        }
    } else {
        // Network connection event
        let ip = format!(
            "{}.{}.{}.{}", 
            (event.dst_ip & 0xFF), 
            (event.dst_ip >> 8 & 0xFF),
            (event.dst_ip >> 16 & 0xFF), 
            (event.dst_ip >> 24 & 0xFF)
        );
        
        info!(
            "Network connection: PID={}, Command={}, Destination={}:{}, Protocol={}",
            event.pid, comm, ip, event.dst_port, event.protocol
        );
        
        // Apply security rules for network connections
        if let Some(threat_level) = ctx.check_network_threat(event.pid, comm, &ip, event.dst_port) {
            if threat_level > 5 {
                warn!(
                    "Suspicious connection detected: {} connecting to {}:{} (threat level: {})",
                    comm, ip, event.dst_port, threat_level
                );
                // Additional security actions
            }
        }
    }
}

// Security context for threat analysis
struct SecurityContext {
    // In a real implementation, this would contain:
    // - Threat intelligence feeds
    // - Behavioral baselines
    // - Policy rules
}

impl SecurityContext {
    fn new() -> Self {
        // Initialize security context with rules, baselines, etc.
        SecurityContext {}
    }
    
    // Check process against security rules
    fn check_process_threat(&self, pid: u32, comm: &str) -> Option<u8> {
        // Simple example - in a real implementation this would be much more sophisticated
        // For instance, checking process signature, parent/child relationships, etc.
        
        // Mock implementation: assign threat level based on process name
        if comm.contains("powershell") || comm.contains("cmd") {
            // Command shells might be suspicious in certain contexts
            Some(3)
        } else if comm.contains("mimikatz") || comm.contains("psexec") {
            // Known security tools/potential threat actors
            Some(9)
        } else {
            Some(1) // Default low threat level
        }
    }
    
    // Check network connection against security rules
    fn check_network_threat(&self, pid: u32, comm: &str, ip: &str, port: u16) -> Option<u8> {
        // Simple example - would integrate with threat intelligence in reality
        
        // Mock implementation: threat level based on destination
        if port == 4444 || port == 4545 {
            // Common reverse shell ports
            Some(8)
        } else if ip.starts_with("10.") && !is_in_allowed_subnet(ip) {
            // Connections to unauthorized internal subnets
            Some(6)
        } else {
            Some(1) // Default low threat level
        }
    }
}

// Helper function for network security rules
fn is_in_allowed_subnet(ip: &str) -> bool {
    // Mock implementation of subnet check
    // In a real system, this would check against actual network policy
    ip.starts_with("10.0.0.") || ip.starts_with("10.0.1.")
}

// Build script and additional helpers would be required for a complete implementation