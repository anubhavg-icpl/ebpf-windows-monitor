// build.rs - Build script for compiling the eBPF program
use std::path::PathBuf;
use std::env;

fn main() {
    // Only build eBPF program if we're not inside the eBPF crate itself
    let cwd = env::current_dir().unwrap();
    let is_ebpf_crate = cwd.file_name()
        .map(|name| name == "ebpf-program")
        .unwrap_or(false);

    if is_ebpf_crate {
        return;
    }

    // Build the eBPF program using aya-build
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    out_dir.push("ebpf-program");

    let clang_path = match env::var("CLANG_PATH") {
        Ok(path) => path,
        Err(_) => "clang".to_string(), // Default to searching PATH
    };

    println!("cargo:rerun-if-changed=ebpf-program/src/main.c");
    aya_build::build_ebpf_program(
        "ebpf-program/src/main.c",
        &out_dir,
        &clang_path,
    ).unwrap();
}

// SETUP INSTRUCTIONS:

/*
### Setup Instructions for Windows eBPF with Rust

#### Prerequisites

1. Install Rust and Cargo:
   - Visit https://rustup.rs/ and follow the installation instructions
   - Add the required targets:
     ```
     rustup target add bpfel-unknown-none
     ```

2. Install LLVM and Clang:
   - Download from https://github.com/llvm/llvm-project/releases
   - Ensure clang is in your PATH

3. Windows eBPF Setup Options:

   Option A - Windows Subsystem for Linux (WSL2):
   - Install WSL2 following Microsoft's instructions
   - Inside WSL, install eBPF tools:
     ```
     sudo apt update
     sudo apt install -y build-essential libelf-dev linux-headers-$(uname -r)
     ```

   Option B - Native Windows eBPF (Preview/Alpha):
   - Install Microsoft's eBPF for Windows:
     - https://github.com/microsoft/ebpf-for-windows
     - Follow their installation instructions
   - Note: This is still in development and may have limitations

#### Project Setup

1. Create the project structure:
   ```
   mkdir -p ebpf-windows-monitor/ebpf-program/src
   cd ebpf-windows-monitor
   ```

2. Create the Cargo.toml, build.rs, and source files as provided in the artifacts

3. Build the project:
   - For WSL approach:
     ```
     cargo build --release
     ```
   - For native Windows:
     Ensure the eBPF runtime is installed and build with:
     ```
     set CLANG_PATH=C:\path\to\clang.exe
     cargo build --release
     ```

#### Running the Monitor

1. If using WSL2, execute with elevated privileges:
   ```
   sudo ./target/release/ebpf-windows-monitor
   ```

2. If using native Windows eBPF, run with Administrator privileges:
   ```
   cd target\release
   ebpf-windows-monitor.exe
   ```

#### Troubleshooting

- Ensure your kernel supports eBPF (for WSL2)
- For native Windows, check that the eBPF runtime is properly installed
- Verify that you have the necessary permissions to load eBPF programs
- Check logs with `RUST_LOG=debug` environment variable:
  ```
  RUST_LOG=debug cargo run --release
  ```

#### Security Considerations

- Running eBPF programs requires elevated privileges, use with caution
- Always validate and review the eBPF code for security implications
- Consider implementing rate limiting and safeguards in your monitoring
- Follow the principle of least privilege when deploying in production
*/