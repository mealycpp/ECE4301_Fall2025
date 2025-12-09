//! PQC Chat GUI - Main Entry Point
//!
//! Simple GUI with controls for the chat client.

#[cfg(feature = "gui")]
use eframe::egui;

#[cfg(feature = "gui")]
fn main() -> Result<(), eframe::Error> {
    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };

    eframe::run_native(
        "PQC Chat - Post-Quantum Secure",
        options,
        Box::new(|cc| Box::new(PqcChatApp::new(cc))),
    )
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("GUI feature not enabled. Build with: cargo build --features gui");
}

#[cfg(feature = "gui")]
struct PqcChatApp {
    // Connection state
    server_host: String,
    server_port: String,
    username: String,
    is_connected: bool,
    is_in_room: bool,

    // Room state
    rooms: Vec<RoomItem>,
    selected_room: Option<usize>,
    new_room_name: String,
    participants: Vec<String>,

    // Media state
    audio_enabled: bool,
    video_enabled: bool,

    // Status
    status_message: String,
}

#[cfg(feature = "gui")]
#[derive(Clone)]
struct RoomItem {
    id: String,
    name: String,
    participants: u32,
    max_participants: u32,
}

#[cfg(feature = "gui")]
impl PqcChatApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            server_host: "127.0.0.1".to_string(),
            server_port: "8443".to_string(),
            username: "User".to_string(),
            is_connected: false,
            is_in_room: false,
            rooms: Vec::new(),
            selected_room: None,
            new_room_name: String::new(),
            participants: Vec::new(),
            audio_enabled: true,
            video_enabled: true,
            status_message: "Disconnected".to_string(),
        }
    }

    fn connect(&mut self) {
        // Stub: In a real implementation, this would connect to the server
        self.is_connected = true;
        self.status_message = format!("Connected as {}", self.username);
        log::info!("Connected to server (stub)");
    }

    fn disconnect(&mut self) {
        self.is_connected = false;
        self.is_in_room = false;
        self.rooms.clear();
        self.participants.clear();
        self.status_message = "Disconnected".to_string();
        log::info!("Disconnected from server");
    }

    fn refresh_rooms(&mut self) {
        // Stub: In a real implementation, this would fetch rooms from the server
        self.rooms = vec![
            RoomItem {
                id: "room-1".to_string(),
                name: "General".to_string(),
                participants: 2,
                max_participants: 10,
            },
            RoomItem {
                id: "room-2".to_string(),
                name: "Development".to_string(),
                participants: 1,
                max_participants: 5,
            },
        ];
        log::info!("Refreshed room list (stub)");
    }

    fn create_room(&mut self) {
        if !self.new_room_name.is_empty() {
            let new_room = RoomItem {
                id: format!("room-{}", self.rooms.len() + 1),
                name: self.new_room_name.clone(),
                participants: 0,
                max_participants: 10,
            };
            self.rooms.push(new_room);
            self.new_room_name.clear();
            log::info!("Created room (stub)");
        }
    }

    fn join_room(&mut self) {
        if let Some(idx) = self.selected_room {
            if idx < self.rooms.len() {
                self.is_in_room = true;
                self.participants = vec![self.username.clone()];
                self.status_message = format!("In room: {}", self.rooms[idx].name);
                log::info!("Joined room {} (stub)", self.rooms[idx].name);
            }
        }
    }

    fn leave_room(&mut self) {
        self.is_in_room = false;
        self.participants.clear();
        self.status_message = format!("Connected as {}", self.username);
        log::info!("Left room (stub)");
    }
}

#[cfg(feature = "gui")]
impl eframe::App for PqcChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("PQC Chat");
                ui.separator();
                ui.label(&self.status_message);
            });
        });

        egui::SidePanel::left("connection_panel")
            .resizable(true)
            .default_width(250.0)
            .show(ctx, |ui| {
                ui.heading("Connection");
                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Server:");
                    ui.add_enabled(
                        !self.is_connected,
                        egui::TextEdit::singleline(&mut self.server_host).desired_width(120.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label("Port:");
                    ui.add_enabled(
                        !self.is_connected,
                        egui::TextEdit::singleline(&mut self.server_port).desired_width(60.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label("Username:");
                    ui.add_enabled(
                        !self.is_connected,
                        egui::TextEdit::singleline(&mut self.username).desired_width(100.0),
                    );
                });

                ui.horizontal(|ui| {
                    if !self.is_connected {
                        if ui.button("Connect").clicked() {
                            self.connect();
                        }
                    } else {
                        if ui.button("Disconnect").clicked() {
                            self.disconnect();
                        }
                    }
                });

                ui.separator();
                ui.heading("Media Controls");

                ui.add_enabled(
                    self.is_in_room,
                    egui::Checkbox::new(&mut self.audio_enabled, "Audio Enabled"),
                );
                ui.add_enabled(
                    self.is_in_room,
                    egui::Checkbox::new(&mut self.video_enabled, "Video Enabled"),
                );
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Rooms");
                if ui
                    .add_enabled(self.is_connected, egui::Button::new("Refresh"))
                    .clicked()
                {
                    self.refresh_rooms();
                }
            });

            ui.separator();

            // Room list
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for (idx, room) in self.rooms.iter().enumerate() {
                        let is_selected = self.selected_room == Some(idx);
                        let text = format!(
                            "{} ({}/{})",
                            room.name, room.participants, room.max_participants
                        );
                        if ui.selectable_label(is_selected, text).clicked() {
                            self.selected_room = Some(idx);
                        }
                    }
                });

            ui.horizontal(|ui| {
                ui.add_enabled(
                    self.is_connected && !self.is_in_room,
                    egui::TextEdit::singleline(&mut self.new_room_name)
                        .hint_text("New room name")
                        .desired_width(150.0),
                );
                if ui
                    .add_enabled(
                        self.is_connected && !self.is_in_room && !self.new_room_name.is_empty(),
                        egui::Button::new("Create"),
                    )
                    .clicked()
                {
                    self.create_room();
                }
            });

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.is_connected && !self.is_in_room && self.selected_room.is_some(),
                        egui::Button::new("Join Room"),
                    )
                    .clicked()
                {
                    self.join_room();
                }
                if ui
                    .add_enabled(self.is_in_room, egui::Button::new("Leave Room"))
                    .clicked()
                {
                    self.leave_room();
                }
            });

            ui.separator();
            ui.heading("Participants");

            for participant in &self.participants {
                ui.label(format!("• {}", participant));
            }
        });
    }
}
