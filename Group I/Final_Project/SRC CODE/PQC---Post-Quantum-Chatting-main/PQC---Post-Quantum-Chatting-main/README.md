# PQC - Post-Quantum Chatting

A LAN-based, post-quantum secure audio/video chat system designed to run on Raspberry Pis.

**Built with Rust and Kyber post-quantum cryptography.**

## Overview

This project implements a secure audio/video chat system with the following features:
- **Kyber1024 post-quantum key exchange** for quantum-resistant encryption
- TLS 1.3 encrypted signaling channel
- DTLS-SRTP encrypted media transport (stub implementation)
- Room-based chat system
- Native egui GUI client
- Designed for Raspberry Pi deployment

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PQC Chat Server (Rust)                   │
│  ┌─────────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  TLS Listener   │  │    Room     │  │   Media         │  │
│  │  + Kyber KEM    │  │   Manager   │  │   Forwarder     │  │
│  └────────┬────────┘  └──────┬──────┘  └───────┬─────────┘  │
│           │                  │                 │            │
│           └──────────────────┴─────────────────┘            │
└─────────────────────────────────────────────────────────────┘
                           │
                    TLS + Kyber / DTLS-SRTP
                           │
┌─────────────────────────────────────────────────────────────┐
│                    PQC Chat Client (Rust)                   │
│  ┌─────────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   Signaling     │  │  AV Capture │  │   Media         │  │
│  │   + Kyber KEM   │  │   (Stubs)   │  │   Transport     │  │
│  └────────┬────────┘  └──────┬──────┘  └───────┬─────────┘  │
│           │                  │                 │            │
│           └──────────────────┴─────────────────┘            │
│                          │                                  │
│                   ┌──────┴──────┐                           │
│                   │  egui GUI   │                           │
│                   └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Server (`src/server/`)
- **main.rs**: TCP TLS listener with Kyber key exchange for signaling connections
- Async Tokio runtime for high performance
- Post-quantum key exchange using Kyber1024

### Client (`src/client/`)
- **main.rs**: TLS signaling client with Kyber key exchange
- Command-line interface for testing

### GUI (`src/gui/`)
- **main.rs**: Basic egui-based native GUI (stub implementation)
- **enhanced_main.rs**: Advanced GUI with real-time features:
  - **Real server communication** with TLS/Kyber key exchange
  - **Live user management** - see all connected users with status
  - **Real-time room updates** - participant join/leave notifications
  - **Multi-panel interface** - users, rooms, and participant panels
  - **Audio/video controls** - working toggle buttons with status indicators
  - **Status message system** - live event notifications with emoji indicators

### Library (`src/`)
- **crypto/kyber.rs**: Kyber1024 key encapsulation mechanism
- **protocol.rs**: JSON signaling message definitions
- **room.rs**: Room and participant management
- **media.rs**: DTLS-SRTP media handling stubs
- **config.rs**: Configuration structures

### Configuration (`config/`)
- **server.toml**: Server configuration (TOML format)
- **client.toml**: Client configuration (TOML format)

### Scripts (`scripts/`)
- **install_server.sh**: Server installation for Raspberry Pi
- **install_client.sh**: Client installation for Raspberry Pi
- **generate_certs.sh**: TLS certificate generation
- **run_server.sh**: Development server launcher
- **run_client.sh**: Development client launcher

### Systemd (`systemd/`)
- **pqc-chat-server.service**: Server systemd service
- **pqc-chat-client@.service**: Client systemd service template

## Quick Start

### Prerequisites

- Rust 1.70+ (install via https://rustup.rs/)
- OpenSSL development libraries
- For GUI: X11/Wayland development libraries

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Vervion/PQC---Post-Quantum-Chatting.git
   cd PQC---Post-Quantum-Chatting
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. Generate TLS certificates:
   ```bash
   ./scripts/generate_certs.sh
   ```

4. Run the server:
   ```bash
   ./target/release/pqc-server
   # Or use the script:
   ./scripts/run_server.sh
   ```

5. Run the client (in another terminal):
   ```bash
   # Interactive terminal client:
   ./target/release/pqc-interactive --host 127.0.0.1
   # Or run the enhanced GUI:
   ./target/release/pqc-enhanced-gui
   ```

### Raspberry Pi Installation

#### Server Installation
```bash
sudo ./scripts/install_server.sh
sudo systemctl enable pqc-chat-server
sudo systemctl start pqc-chat-server
```

#### Client Installation
```bash
sudo ./scripts/install_client.sh
# Edit /etc/pqc-chat/client.toml with server address
/opt/pqc-chat/bin/pqc-gui
```

## Running Tests

```bash
# Run Rust unit tests
cargo test

# Run Python integration tests
python3 -m unittest discover tests/
```

## Configuration

### Server Configuration (`config/server.toml`)

```toml
signaling_host = "0.0.0.0"
signaling_port = 8443
audio_port = 10000
video_port = 10001
certfile = "server.crt"
keyfile = "server.key"
default_max_participants = 10
log_level = "info"
```

### Client Configuration (`config/client.toml`)

```toml
server_host = "192.168.1.100"
signaling_port = 8443
default_username = "RaspberryPi"
log_level = "info"

[video]
width = 640
height = 480
fps = 30

[audio]
sample_rate = 48000
channels = 1
```

## Protocol

### Kyber Key Exchange

Before signaling begins, a post-quantum key exchange is performed:

1. Client generates Kyber1024 key pair
2. Client sends public key to server (`KeyExchangeInit`)
3. Server encapsulates shared secret and returns ciphertext (`KeyExchangeResponse`)
4. Client decapsulates to derive same shared secret
5. Shared secret can be used for additional encryption layers

### Signaling Messages

The client and server communicate via JSON messages over TLS:

| Message Type | Direction | Description |
|--------------|-----------|-------------|
| key_exchange_init | C→S | Send Kyber public key |
| key_exchange_response | S→C | Return ciphertext |
| login | C→S | User authentication |
| list_rooms | C→S | Request room list |
| create_room | C→S | Create a new room |
| join_room | C→S | Join an existing room |
| leave_room | C→S | Leave current room |
| toggle_audio | C→S | Toggle audio state |
| toggle_video | C→S | Toggle video state |
| participant_joined | S→C | Notification of new participant |
| participant_left | S→C | Notification of participant leaving |

## Implementation Status

- ✅ Rust server with TLS listener
- ✅ Kyber1024 post-quantum key exchange
- ✅ Basic room manager
- ✅ DTLS-SRTP media forwarder stubs
- ✅ Rust signaling client
- ✅ Audio/video capture stubs
- ✅ DTLS-SRTP media transport stubs
- ✅ egui native GUI
- ✅ TOML configuration
- ✅ Systemd service files
- ✅ Installation scripts for Raspberry Pi

## Future Enhancements

- [x] **Enhanced GUI with Real-time User Management** - Live participant tracking and status updates
- [x] **Real Server Communication** - Actual TLS/Kyber communication instead of stub implementations  
- [x] **Live Room Management** - Real-time room creation, joining, and participant updates
- [x] **User Status Indicators** - Audio/video status with emoji indicators
- [x] **Multi-panel Interface** - Dedicated panels for users, rooms, and controls
- [ ] Use Kyber shared secret for additional media encryption
- [x] **Text Chat** - Real-time text messaging in rooms with timestamp support
- [ ] **Audio Communication Implementation** - See [Audio Implementation Guide](#audio-implementation-guide) below
- [ ] Real DTLS-SRTP implementation  
- [ ] Audio/video encoding (Opus, VP8/VP9)
- [ ] ICE/STUN/TURN support for NAT traversal
- [ ] End-to-end encryption for media using Kyber-derived keys
- [ ] Screen sharing

## Audio Implementation Guide

The audio communication infrastructure is in place but requires actual audio capture and playback implementation. Here's how to add real audio functionality:

### Recommended Approach: Using `cpal`

`cpal` (Cross-Platform Audio Library) is ideal for low-level audio control:

```toml
# Add to Cargo.toml
[dependencies]
cpal = "0.15"
ringbuf = "0.3"  # For audio buffering
```

#### Audio Capture Implementation

```rust
// In src/audio/capture.rs
use cpal::{Device, Stream, StreamConfig};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

pub struct AudioCapture {
    stream: Stream,
    // Channel for sending audio data to GUI
    audio_sender: mpsc::UnboundedSender<Vec<u8>>,
}

impl AudioCapture {
    pub fn new(audio_sender: mpsc::UnboundedSender<Vec<u8>>) -> Result<Self, Box<dyn std::error::Error>> {
        let host = cpal::default_host();
        let device = host.default_input_device().ok_or("No input device")?;
        let config = device.default_input_config()?;
        
        let stream = device.build_input_stream(
            &config.into(),
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                // Convert f32 samples to bytes and send
                let bytes: Vec<u8> = data.iter()
                    .flat_map(|&sample| (sample * i16::MAX as f32) as i16 as u16.to_le_bytes())
                    .collect();
                let _ = audio_sender.send(bytes);
            },
            |err| eprintln!("Audio capture error: {}", err),
            None,
        )?;
        
        stream.play()?;
        Ok(AudioCapture { stream, audio_sender })
    }
}
```

#### Audio Playback Implementation

```rust
// In src/audio/playback.rs
use ringbuf::{HeapRb, HeapProducer, HeapConsumer};

pub struct AudioPlayback {
    stream: Stream,
    producer: HeapProducer<f32>,
}

impl AudioPlayback {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let ring_buffer = HeapRb::<f32>::new(1024 * 16); // 16KB buffer
        let (producer, consumer) = ring_buffer.split();
        
        let host = cpal::default_host();
        let device = host.default_output_device().ok_or("No output device")?;
        let config = device.default_output_config()?;
        
        let stream = device.build_output_stream(
            &config.into(),
            move |output: &mut [f32], _: &cpal::OutputCallbackInfo| {
                for sample in output.iter_mut() {
                    *sample = consumer.pop().unwrap_or(0.0);
                }
            },
            |err| eprintln!("Audio playback error: {}", err),
            None,
        )?;
        
        stream.play()?;
        Ok(AudioPlayback { stream, producer })
    }
    
    pub fn play_audio(&mut self, audio_data: &[u8]) {
        // Convert bytes back to f32 samples
        for chunk in audio_data.chunks_exact(2) {
            let sample = i16::from_le_bytes([chunk[0], chunk[1]]) as f32 / i16::MAX as f32;
            let _ = self.producer.push(sample);
        }
    }
}
```

### Alternative: Using `rodio`

`rodio` is better for higher-level audio playback:

```toml
[dependencies]
rodio = "0.17"
cpal = "0.15"  # Still needed for capture
```

```rust
// For audio playback with rodio
use rodio::{Decoder, OutputStream, Sink};

pub fn play_received_audio(audio_data: Vec<u8>) {
    let (_stream, stream_handle) = OutputStream::try_default().unwrap();
    let sink = Sink::try_new(&stream_handle).unwrap();
    
    // Convert raw audio data to a format rodio can play
    let cursor = std::io::Cursor::new(audio_data);
    let source = Decoder::new(cursor).unwrap();
    sink.append(source);
    sink.sleep_until_end();
}
```

### Integration Points

1. **In GuiCommand enum**: Add `StartAudioCapture` and `StopAudioCapture`
2. **In communication_task**: Handle incoming `AudioDataReceived` messages and send to playback
3. **In GUI audio toggle**: Start/stop audio capture based on button state
4. **In server**: Ensure audio forwarding is working (already implemented)

### Audio Quality Settings

```rust
// Recommended settings for voice chat
const SAMPLE_RATE: u32 = 16000;  // 16kHz for voice
const CHANNELS: u16 = 1;         // Mono
const BITS_PER_SAMPLE: u16 = 16; // 16-bit
```

### Performance Considerations

- Use `ringbuf` for lock-free audio buffering
- Implement audio compression (Opus codec) for network efficiency
- Add echo cancellation and noise reduction if needed
- Buffer audio data to handle network jitter

The protocol infrastructure (`AudioData` and `AudioDataReceived` messages) is already implemented and working. Adding the above audio capture/playback code will complete the audio communication system.

## Security

This project uses **Kyber1024**, a NIST-selected post-quantum key encapsulation mechanism that is resistant to attacks from both classical and quantum computers.

## License

MIT License - see [LICENSE](LICENSE) for details.
