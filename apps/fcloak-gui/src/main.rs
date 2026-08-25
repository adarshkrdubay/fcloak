mod drive;
mod oauth;
mod vault;

use std::{
    fs,
    time::{Duration, Instant},
};

use eframe::egui;

use drive::{DriveClient, DriveFile};
use oauth::GoogleAuth;
use vault::{Vault, VaultFile, format_size};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Vault,
    Drive,
}

struct FcloakApp {
    vault: Vault,
    auth: GoogleAuth,

    page: Page,

    unlocked: bool,
    master_password: String,
    confirm_password: String,
    session_password: String,

    local_files: Vec<VaultFile>,
    selected_local: Option<usize>,

    drive_files: Vec<DriveFile>,
    selected_drive: Option<usize>,

    drive: Option<DriveClient>,

    search: String,

    status: String,
    status_error: bool,

    setup_mode: bool,

    // Automatically lock the vault after five minutes
    // without user activity.
    last_activity: Instant,
}

impl FcloakApp {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let vault = Vault::new()?;

        let setup_mode = !vault.is_initialized();

        let mut auth = GoogleAuth::new()?;

        let mut status = String::new();

        if !setup_mode {
            match auth.restore_saved_session() {
                Ok(true) => {
                    status = "Google Drive session restored automatically.".to_string();
                }

                Ok(false) => {}

                Err(error) => {
                    status = format!("Google session needs reconnect: {error}");
                }
            }
        }

        let mut app = Self {
            vault,
            auth,

            page: Page::Vault,

            unlocked: false,
            master_password: String::new(),
            confirm_password: String::new(),
            session_password: String::new(),

            local_files: Vec::new(),
            selected_local: None,

            drive_files: Vec::new(),
            selected_drive: None,

            drive: None,

            search: String::new(),

            status,
            status_error: false,

            setup_mode,
            last_activity: Instant::now(),
        };

        if app.auth.is_connected() {
            app.rebuild_drive_client();

            if let Err(error) = app.refresh_drive() {
                app.status = format!("Drive connection restored, but refresh failed: {error}");
                app.status_error = true;
            }
        }

        Ok(app)
    }

    fn rebuild_drive_client(&mut self) {
        self.drive = None;

        if let Ok(token) = self.auth.access_token() {
            self.drive = Some(DriveClient::new(token));
        }
    }

    fn set_status(&mut self, message: impl Into<String>) {
        self.status = message.into();
        self.status_error = false;
    }

    fn set_error(&mut self, error: impl ToString) {
        self.status = error.to_string();
        self.status_error = true;
    }

    fn refresh_vault(&mut self) {
        match self.vault.list_files() {
            Ok(files) => {
                self.local_files = files;

                if self
                    .selected_local
                    .is_some_and(|index| index >= self.local_files.len())
                {
                    self.selected_local = None;
                }
            }

            Err(error) => {
                self.set_error(error);
            }
        }
    }

    fn refresh_drive(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let token = self.auth.access_token()?;

        self.drive = Some(DriveClient::new(token));

        let files = self
            .drive
            .as_ref()
            .ok_or("Drive client unavailable")?
            .list_files()?;

        self.drive_files = files;

        self.selected_drive = None;

        self.set_status(format!(
            "Google Drive refreshed: {} encrypted files.",
            self.drive_files.len()
        ));

        Ok(())
    }

    fn connect_drive(&mut self) {
        self.set_status("Opening Google sign-in...");

        match self.auth.connect_interactive() {
            Ok(()) => {
                self.rebuild_drive_client();

                match self.refresh_drive() {
                    Ok(()) => {
                        self.set_status("Google Drive connected and synchronized.");
                    }

                    Err(error) => {
                        self.set_error(error);
                    }
                }
            }

            Err(error) => {
                self.set_error(error);
            }
        }
    }

    fn disconnect_drive(&mut self) {
        match self.auth.disconnect() {
            Ok(()) => {
                self.drive = None;
                self.drive_files.clear();
                self.selected_drive = None;

                self.set_status("Google Drive disconnected.");
            }

            Err(error) => {
                self.set_error(error);
            }
        }
    }

    fn import_file(&mut self) {
        if !self.unlocked {
            return;
        }

        let Some(source) = rfd::FileDialog::new()
            .set_title("Select file to encrypt")
            .pick_file()
        else {
            return;
        };

        let password = self.session_password.clone();

        match self.vault.import_file(&source, password.as_bytes()) {
            Ok(path) => {
                self.refresh_vault();

                self.set_status(format!("Encrypted successfully: {}", path.display()));
            }

            Err(error) => {
                self.set_error(error);
            }
        }
    }

    fn export_local(&mut self) {
        let Some(index) = self.selected_local else {
            return;
        };

        let Some(file) = self.local_files.get(index) else {
            return;
        };

        let default_name = file.name.clone();

        let Some(destination) = rfd::FileDialog::new()
            .set_title("Export decrypted file")
            .set_file_name(&default_name)
            .save_file()
        else {
            return;
        };

        let encrypted = file.encrypted_path.clone();

        match self
            .vault
            .export_file(&encrypted, &destination, self.session_password.as_bytes())
        {
            Ok(()) => {
                self.set_status(format!(
                    "Decrypted and exported to {}",
                    destination.display()
                ));
            }

            Err(error) => {
                let _ = std::fs::remove_file(&destination);

                self.set_error(error);
            }
        }
    }

    fn delete_local(&mut self) {
        let Some(index) = self.selected_local else {
            return;
        };

        let Some(file) = self.local_files.get(index) else {
            return;
        };

        let encrypted_path = file.encrypted_path.clone();

        match self.vault.delete_file(&encrypted_path) {
            Ok(()) => {
                self.selected_local = None;
                self.refresh_vault();

                self.set_status("Encrypted file deleted from local vault.");
            }

            Err(error) => {
                self.set_error(error);
            }
        }
    }

    fn upload_selected_to_drive(&mut self) {
        let Some(index) = self.selected_local else {
            self.set_error("Select an encrypted file first.");
            return;
        };

        let Some(local_file) = self.local_files.get(index) else {
            self.set_error("Selected local file no longer exists.");
            return;
        };

        let file = local_file.encrypted_path.clone();

        if !file.is_file() {
            self.set_error("Encrypted file no longer exists.");
            return;
        }

        if !self.auth.is_connected() {
            self.set_error("Google Drive is not connected.");
            return;
        }

        self.set_status("Uploading encrypted container to Google Drive...");

        let result = match self.drive.as_ref() {
            Some(drive) => drive.upload_file(&file),
            None => {
                self.set_error("Google Drive client unavailable.");
                return;
            }
        };

        match result {
            Ok(uploaded) => {
                // Delete the local encrypted staging copy ONLY after
                // Google Drive confirms that the upload succeeded.
                if let Err(error) = fs::remove_file(&file) {
                    self.set_error(format!(
                        "Upload succeeded, but the local .fcloak copy could not be removed: {error}"
                    ));
                    return;
                }

                self.selected_local = None;
                self.refresh_vault();

                if let Err(error) = self.refresh_drive() {
                    self.set_error(format!(
                        "Uploaded successfully, but Drive refresh failed: {error}"
                    ));
                    return;
                }

                self.set_status(format!(
                    "Uploaded {}. Local encrypted copy removed.",
                    uploaded.name
                ));
            }

            Err(error) => {
                // Keep the local encrypted copy if upload fails.
                self.set_error(format!("Upload failed: {error}"));
            }
        }
    }

    fn download_drive(&mut self) {
        let Some(index) = self.selected_drive else {
            self.set_error("Select a Google Drive file first.");
            return;
        };

        let Some(file) = self.drive_files.get(index) else {
            return;
        };

        let Some(destination) = rfd::FileDialog::new()
            .set_title("Download encrypted FCLOAK file")
            .set_file_name(&file.name)
            .save_file()
        else {
            return;
        };

        let file_id = file.id.clone();

        self.rebuild_drive_client();

        let Some(drive) = self.drive.as_ref() else {
            self.set_error("Google Drive client unavailable.");
            return;
        };

        match drive.download_file(&file_id, &destination) {
            Ok(()) => {
                self.set_status(format!(
                    "Encrypted file downloaded to {}",
                    destination.display()
                ));
            }

            Err(error) => {
                let _ = std::fs::remove_file(&destination);

                self.set_error(error);
            }
        }
    }

    fn download_and_decrypt_drive(&mut self) {
        let Some(index) = self.selected_drive else {
            self.set_error("Select a Drive file first.");
            return;
        };

        if self.session_password.is_empty() {
            self.set_error("Vault session is locked. Unlock FCLOAK first.");
            return;
        }

        let Some(file) = self.drive_files.get(index).cloned() else {
            self.set_error("Selected Drive file no longer exists.");
            return;
        };

        if !file.name.to_lowercase().ends_with(".fcloak") {
            self.set_error("This is not a FCLOAK encrypted container.");
            return;
        }

        let original_name = original_filename(&file.name);

        let Some(destination) = rfd::FileDialog::new()
            .set_title("Save decrypted file")
            .set_file_name(&original_name)
            .save_file()
        else {
            return;
        };

        let temp_path = std::env::temp_dir().join(format!(
            "fcloak-{}-{}.fcloak",
            unique_timestamp(),
            sanitize_temp_name(&file.name)
        ));

        self.set_status("Downloading encrypted container...");

        self.rebuild_drive_client();

        let Some(drive) = self.drive.as_ref() else {
            self.set_error("Google Drive client unavailable.");
            return;
        };

        if let Err(error) = drive.download_file(&file.id, &temp_path) {
            let _ = fs::remove_file(&temp_path);
            let _ = fs::remove_file(&destination);
            self.set_error(format!("Download failed: {error}"));
            return;
        }

        self.set_status("Decrypting locally...");

        let result =
            self.vault
                .export_file(&temp_path, &destination, self.session_password.as_bytes());

        // Always remove the temporary encrypted container.
        let _ = fs::remove_file(&temp_path);

        match result {
            Ok(()) => {
                self.set_status(format!(
                    "Decrypted successfully to {}. Encrypted Drive copy remains protected.",
                    destination.display()
                ));
            }
            Err(error) => {
                let _ = fs::remove_file(&destination);
                self.set_error(format!("Decryption failed: {error}"));
            }
        }
    }

    fn delete_drive_file(&mut self) {
        let Some(index) = self.selected_drive else {
            self.set_error("Select a Google Drive file first.");
            return;
        };

        let Some(file) = self.drive_files.get(index) else {
            return;
        };

        let file_id = file.id.clone();
        let file_name = file.name.clone();

        self.rebuild_drive_client();

        let Some(drive) = self.drive.as_ref() else {
            self.set_error("Google Drive client unavailable.");
            return;
        };

        match drive.delete_file(&file_id) {
            Ok(()) => {
                self.selected_drive = None;

                if let Err(error) = self.refresh_drive() {
                    self.set_error(error);
                } else {
                    self.set_status(format!("{} deleted from Google Drive.", file_name));
                }
            }

            Err(error) => {
                self.set_error(error);
            }
        }
    }

    fn lock(&mut self) {
        self.unlocked = false;
        self.master_password.clear();
        self.confirm_password.clear();
        self.session_password.clear();

        self.selected_local = None;
        self.selected_drive = None;

        self.set_status("Vault locked.");
    }

    fn unlock(&mut self) {
        let password = self.master_password.clone();

        match self.vault.verify_password(&password) {
            Ok(true) => {
                self.unlocked = true;
                self.session_password = password;

                self.master_password.clear();
                self.confirm_password.clear();

                self.refresh_vault();

                self.last_activity = Instant::now();
                self.set_status("Vault unlocked.");
            }

            Ok(false) => {
                self.master_password.clear();

                self.set_error("Incorrect master password.");
            }

            Err(error) => {
                self.master_password.clear();

                self.set_error(error);
            }
        }
    }

    fn password_strength(password: &str) -> (bool, bool, bool, bool, bool) {
        let long_enough = password.chars().count() >= 12;
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

        (long_enough, has_upper, has_lower, has_digit, has_special)
    }

    fn password_is_strong(password: &str) -> bool {
        let (long_enough, has_upper, has_lower, has_digit, has_special) =
            Self::password_strength(password);

        long_enough && has_upper && has_lower && has_digit && has_special
    }

    fn initialize_vault(&mut self) {
        if self.master_password.is_empty() {
            self.set_error("Master password cannot be empty.");
            return;
        }

        if !Self::password_is_strong(&self.master_password) {
            self.set_error(
                "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
            );
            return;
        }

        if self.master_password != self.confirm_password {
            self.set_error("Master passwords do not match.");
            return;
        }

        match self.vault.initialize(&self.master_password) {
            Ok(()) => {
                self.setup_mode = false;
                self.unlocked = true;
                self.session_password = self.master_password.clone();

                self.master_password.clear();
                self.confirm_password.clear();

                self.refresh_vault();

                self.last_activity = Instant::now();
                self.set_status("FCLOAK vault created successfully.");
            }

            Err(error) => {
                self.set_error(error);
            }
        }
    }

    fn update_activity_timer(&mut self, ctx: &egui::Context) {
        if !self.unlocked {
            return;
        }

        let has_activity = ctx.input(|input| !input.events.is_empty());

        if has_activity {
            self.last_activity = Instant::now();
        }

        const AUTO_LOCK_AFTER: Duration = Duration::from_secs(5 * 60);

        if Instant::now().duration_since(self.last_activity) >= AUTO_LOCK_AFTER {
            self.lock();
            self.set_status("FCLOAK automatically locked after 5 minutes of inactivity.");
        }
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_bar")
            .exact_height(66.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(20.0);

                    ui.heading(egui::RichText::new("FCLOAK").size(25.0).strong());

                    ui.label(egui::RichText::new("SECURE VAULT").size(11.0).weak());

                    ui.add_space(25.0);

                    if self.auth.is_connected() {
                        ui.label(
                            egui::RichText::new("● Google Drive Connected")
                                .color(egui::Color32::from_rgb(80, 210, 130))
                                .strong(),
                        );
                    } else {
                        ui.label(egui::RichText::new("○ Google Drive").weak());
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.unlocked {
                            if ui.button("Lock").clicked() {
                                self.lock();
                            }
                        }
                    });
                });
            });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .default_width(245.0)
            .show(ctx, |ui| {
                ui.add_space(22.0);

                ui.label(egui::RichText::new("VAULT").size(12.0).strong().weak());

                ui.add_space(10.0);

                if ui
                    .add(
                        egui::Button::selectable(self.page == Page::Vault, "Vault  •  All Files")
                            .min_size(egui::vec2(210.0, 40.0)),
                    )
                    .clicked()
                {
                    self.page = Page::Vault;
                }

                ui.add_space(6.0);

                if ui
                    .add(
                        egui::Button::selectable(
                            self.page == Page::Drive,
                            "Cloud  •  Google Drive",
                        )
                        .min_size(egui::vec2(210.0, 40.0)),
                    )
                    .clicked()
                {
                    self.page = Page::Drive;

                    if self.auth.is_connected() {
                        if let Err(error) = self.refresh_drive() {
                            self.set_error(error);
                        }
                    }
                }

                ui.add_space(30.0);

                ui.label(egui::RichText::new("STORAGE").size(12.0).strong().weak());

                ui.add_space(8.0);

                egui::Frame::default()
                    .stroke(egui::Stroke::new(
                        1.0_f32,
                        ui.visuals().widgets.noninteractive.bg_stroke.color,
                    ))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label("FILES");

                        ui.label(
                            egui::RichText::new(self.local_files.len().to_string())
                                .size(22.0)
                                .strong(),
                        );
                    });

                ui.add_space(10.0);

                let total_size: u64 = self.local_files.iter().map(|f| f.size).sum();

                egui::Frame::default()
                    .stroke(egui::Stroke::new(
                        1.0_f32,
                        ui.visuals().widgets.noninteractive.bg_stroke.color,
                    ))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label("USED");

                        ui.label(
                            egui::RichText::new(format_size(total_size))
                                .size(17.0)
                                .strong(),
                        );
                    });

                ui.add_space(28.0);

                ui.separator();

                ui.add_space(20.0);

                ui.label(egui::RichText::new("CLOUD").size(12.0).strong().weak());

                ui.add_space(10.0);

                if self.auth.is_connected() {
                    ui.label(
                        egui::RichText::new("● Google Drive")
                            .color(egui::Color32::from_rgb(80, 210, 130))
                            .strong(),
                    );

                    ui.label(format!("{} encrypted files", self.drive_files.len()));

                    ui.add_space(8.0);

                    if ui.button("Open Drive").clicked() {
                        self.page = Page::Drive;

                        if let Err(error) = self.refresh_drive() {
                            self.set_error(error);
                        }
                    }

                    if ui.button("Refresh Drive").clicked() {
                        if let Err(error) = self.refresh_drive() {
                            self.set_error(error);
                        }
                    }

                    if ui.button("Disconnect").clicked() {
                        self.disconnect_drive();
                    }
                } else {
                    ui.label(egui::RichText::new("Google Drive not connected").weak());

                    ui.add_space(8.0);

                    if ui.button("Connect Google Drive").clicked() {
                        self.connect_drive();
                    }
                }

                ui.add_space(25.0);

                ui.separator();

                ui.add_space(12.0);

                if ui.button("Refresh Vault").clicked() {
                    self.refresh_vault();
                }

                ui.add_space(12.0);

                if !self.status.is_empty() {
                    let color = if self.status_error {
                        egui::Color32::from_rgb(240, 100, 100)
                    } else {
                        egui::Color32::from_rgb(100, 190, 240)
                    };

                    ui.label(egui::RichText::new(&self.status).color(color).small());
                }
            });
    }

    fn vault_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(egui::RichText::new("My Files").size(30.0).strong());

            ui.add_space(8.0);

            ui.label(
                egui::RichText::new(format!("{} encrypted files", self.local_files.len()))
                    .size(13.0)
                    .weak(),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Import and encrypt a new file.
                if ui
                    .add_sized([155.0, 38.0], egui::Button::new("Import & Encrypt"))
                    .clicked()
                {
                    self.import_file();
                }

                // Upload the currently selected encrypted file.
                if ui
                    .add_enabled(
                        self.selected_local.is_some() && self.auth.is_connected(),
                        egui::Button::new("Upload to Drive"),
                    )
                    .clicked()
                {
                    self.upload_selected_to_drive();
                }

                // Open the Drive browser.
                if ui
                    .add_sized([150.0, 38.0], egui::Button::new("Open Google Drive"))
                    .clicked()
                {
                    self.page = Page::Drive;

                    if let Err(error) = self.refresh_drive() {
                        self.set_error(error);
                    }
                }
            });
        });

        ui.add_space(18.0);

        ui.horizontal(|ui| {
            ui.label("Search");

            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search encrypted files...")
                    .desired_width(360.0),
            );

            if !self.search.is_empty() && ui.button("Clear").clicked() {
                self.search.clear();
            }
        });

        ui.add_space(18.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (index, file) in self.local_files.iter().enumerate() {
                    if !self.search.is_empty()
                        && !file
                            .name
                            .to_lowercase()
                            .contains(&self.search.to_lowercase())
                    {
                        continue;
                    }

                    let selected = self.selected_local == Some(index);

                    egui::Frame::default()
                        .inner_margin(egui::Margin::symmetric(8, 5))
                        .show(ui, |ui| {
                            let response = ui.add(
                                egui::Button::selectable(
                                    selected,
                                    format!("  {}    {}", file.name, format_size(file.size)),
                                )
                                .min_size(egui::vec2(ui.available_width(), 58.0)),
                            );

                            if response.clicked() {
                                self.selected_local = Some(index);
                            }
                        });
                }
            });

        ui.add_space(12.0);

        egui::Frame::default()
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                let has_selection = self.selected_local.is_some();

                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new(if has_selection {
                            "Encrypted file selected"
                        } else {
                            "Select an encrypted file"
                        })
                        .size(12.0)
                        .weak(),
                    );

                    ui.add_space(12.0);

                    if ui
                        .add_enabled(has_selection, egui::Button::new("Export & Decrypt"))
                        .clicked()
                    {
                        self.export_local();
                    }

                    if ui
                        .add_enabled(
                            has_selection && self.auth.is_connected(),
                            egui::Button::new("Upload Encrypted to Drive"),
                        )
                        .clicked()
                    {
                        self.upload_selected_to_drive();
                    }

                    if ui
                        .add_enabled(has_selection, egui::Button::new("Delete"))
                        .clicked()
                    {
                        self.delete_local();
                    }
                });
            });
    }

    fn drive_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(egui::RichText::new("Google Drive").size(30.0).strong());

            ui.add_space(8.0);

            ui.label(
                egui::RichText::new(format!("{} encrypted files", self.drive_files.len()))
                    .size(13.0)
                    .weak(),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_sized([130.0, 38.0], egui::Button::new("Refresh Drive"))
                    .clicked()
                {
                    if let Err(error) = self.refresh_drive() {
                        self.set_error(error);
                    }
                }

                if ui
                    .add_sized([145.0, 38.0], egui::Button::new("Back to Vault"))
                    .clicked()
                {
                    self.page = Page::Vault;
                }
            });
        });

        ui.add_space(16.0);

        ui.horizontal(|ui| {
            ui.label("Search");

            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search Drive files...")
                    .desired_width(360.0),
            );

            if !self.search.is_empty() && ui.button("Clear").clicked() {
                self.search.clear();
            }
        });

        ui.add_space(10.0);

        // ACTION BAR IS ABOVE THE FILE LIST so it is always visible.
        let has_selection = self.selected_drive.is_some();

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(24, 29, 34))
            .stroke(egui::Stroke::new(
                1.0_f32,
                ui.visuals().widgets.noninteractive.bg_stroke.color,
            ))
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let selection_text = if let Some(index) = self.selected_drive {
                        self.drive_files
                            .get(index)
                            .map(|f| format!("Selected: {}", f.name))
                            .unwrap_or_else(|| "Selection unavailable".to_string())
                    } else {
                        "Select an encrypted Drive file".to_string()
                    };

                    ui.label(egui::RichText::new(selection_text).size(12.0).weak());

                    ui.add_space(12.0);

                    if ui
                        .add_enabled(
                            has_selection && self.unlocked,
                            egui::Button::new("Download & Decrypt"),
                        )
                        .clicked()
                    {
                        self.download_and_decrypt_drive();
                    }

                    if ui
                        .add_enabled(has_selection, egui::Button::new("Download Encrypted"))
                        .clicked()
                    {
                        self.download_drive();
                    }

                    if ui
                        .add_enabled(has_selection, egui::Button::new("Delete from Drive"))
                        .clicked()
                    {
                        self.delete_drive_file();
                    }

                    if !self.unlocked {
                        ui.label(
                            egui::RichText::new("Unlock FCLOAK to decrypt")
                                .size(11.0)
                                .weak(),
                        );
                    }
                });
            });

        ui.add_space(10.0);

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(20, 25, 30))
            .stroke(egui::Stroke::new(
                1.0_f32,
                ui.visuals().widgets.noninteractive.bg_stroke.color,
            ))
            .inner_margin(egui::Margin::symmetric(12, 9))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("SECURE CLOUD")
                            .size(11.0)
                            .strong()
                            .color(egui::Color32::from_rgb(80, 210, 130)),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(
                            "Only encrypted .fcloak containers are stored in Google Drive. Decryption happens locally.",
                        )
                        .small()
                        .weak(),
                    );
                });
            });

        ui.add_space(10.0);

        egui::Frame::default()
            .stroke(egui::Stroke::new(
                1.0_f32,
                ui.visuals().widgets.noninteractive.bg_stroke.color,
            ))
            .inner_margin(10.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("drive_file_list")
                    .auto_shrink([false, false])
                    .max_height(360.0)
                    .show(ui, |ui| {
                        if self.drive_files.is_empty() {
                            ui.vertical_centered(|ui| {
                                ui.add_space(60.0);

                                ui.label(
                                    egui::RichText::new("No FCLOAK files in Google Drive")
                                        .size(18.0)
                                        .weak(),
                                );

                                ui.add_space(8.0);

                                ui.label(
                                    egui::RichText::new(
                                        "Upload encrypted files from My Files, then download and decrypt them here.",
                                    )
                                    .weak(),
                                );
                            });
                        }

                        for (index, file) in self.drive_files.iter().enumerate() {
                            if !self.search.is_empty()
                                && !file
                                    .name
                                    .to_lowercase()
                                    .contains(&self.search.to_lowercase())
                            {
                                continue;
                            }

                            let selected = self.selected_drive == Some(index);

                            let response = ui.add(
                                egui::Button::selectable(
                                    selected,
                                    format!("  {}    {}", file.name, file.display_size()),
                                )
                                .min_size(egui::vec2(ui.available_width(), 58.0)),
                            );

                            if response.clicked() {
                                self.selected_drive = Some(index);
                            }
                        }
                    });
            });

        ui.add_space(20.0);

        // Secondary action area at the bottom as well. The primary action
        // buttons above remain visible even when the list is long.
        egui::Frame::default()
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new(if has_selection {
                            "Drive file selected"
                        } else {
                            "Select an encrypted Drive file"
                        })
                        .size(12.0)
                        .weak(),
                    );

                    ui.add_space(12.0);

                    if ui
                        .add_enabled(
                            has_selection && self.unlocked,
                            egui::Button::new("Download & Decrypt"),
                        )
                        .clicked()
                    {
                        self.download_and_decrypt_drive();
                    }

                    if ui
                        .add_enabled(has_selection, egui::Button::new("Download Encrypted"))
                        .clicked()
                    {
                        self.download_drive();
                    }

                    if ui
                        .add_enabled(has_selection, egui::Button::new("Delete from Drive"))
                        .clicked()
                    {
                        self.delete_drive_file();
                    }
                });
            });
    }

    fn footer(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("footer")
            .exact_height(30.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new("FCLOAK")
                            .size(10.0)
                            .strong()
                            .color(egui::Color32::from_rgb(100, 190, 240)),
                    );
                    ui.label(
                        egui::RichText::new("Secure encrypted vault")
                            .size(10.0)
                            .weak(),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new("Made by TheWIZs").size(10.0).weak());
                    });
                });
            });
    }

    fn locked_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(110.0);

                ui.heading(egui::RichText::new("FCLOAK").size(34.0).strong());

                ui.add_space(8.0);

                if self.setup_mode {
                    ui.label(egui::RichText::new("Create your master password").size(18.0));

                    ui.add_space(30.0);

                    ui.label("Master password");

                    ui.add(
                        egui::TextEdit::singleline(&mut self.master_password)
                            .password(true)
                            .desired_width(320.0),
                    );

                    let (long_enough, has_upper, has_lower, has_digit, has_special) =
                        Self::password_strength(&self.master_password);

                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new("Password requirements")
                            .small()
                            .strong(),
                    );

                    let requirement = |ui: &mut egui::Ui, ok: bool, text: &str| {
                        let symbol = if ok { "✓" } else { "○" };
                        let color = if ok {
                            egui::Color32::from_rgb(80, 210, 130)
                        } else {
                            ui.visuals().weak_text_color()
                        };

                        ui.label(
                            egui::RichText::new(format!("{symbol} {text}"))
                                .small()
                                .color(color),
                        );
                    };

                    requirement(ui, long_enough, "At least 12 characters");
                    requirement(ui, has_upper, "One uppercase letter");
                    requirement(ui, has_lower, "One lowercase letter");
                    requirement(ui, has_digit, "One number");
                    requirement(ui, has_special, "One special character");

                    ui.add_space(10.0);

                    ui.label("Confirm password");

                    ui.add(
                        egui::TextEdit::singleline(&mut self.confirm_password)
                            .password(true)
                            .desired_width(320.0),
                    );

                    ui.add_space(20.0);

                    if ui
                        .add_sized([320.0, 42.0], egui::Button::new("Create Secure Vault"))
                        .clicked()
                    {
                        self.initialize_vault();
                    }
                } else {
                    ui.label(egui::RichText::new("Unlock your secure vault").size(18.0));

                    ui.add_space(30.0);

                    ui.label("Master password");

                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.master_password)
                            .password(true)
                            .desired_width(320.0),
                    );

                    ui.add_space(20.0);

                    if ui
                        .add_sized([320.0, 42.0], egui::Button::new("Unlock FCLOAK"))
                        .clicked()
                        || response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    {
                        self.unlock();
                    }
                }

                ui.add_space(25.0);

                if !self.status.is_empty() {
                    let color = if self.status_error {
                        egui::Color32::from_rgb(240, 100, 100)
                    } else {
                        egui::Color32::from_rgb(100, 190, 240)
                    };

                    ui.label(egui::RichText::new(&self.status).color(color));
                }
            });
        });
    }
}

impl eframe::App for FcloakApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());

        // Poll once per second so the five-minute lock happens even
        // when the user simply leaves the application untouched.
        ctx.request_repaint_after(Duration::from_secs(1));

        if self.unlocked {
            self.update_activity_timer(ctx);
        }

        if self.setup_mode || !self.unlocked {
            self.footer(ctx);
            self.locked_screen(ctx);
            return;
        }

        self.footer(ctx);
        self.top_bar(ctx);
        self.sidebar(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("main_content_scroll")
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .show(ui, |ui| {
                    ui.add_space(25.0);
                    ui.add_space(10.0);

                    match self.page {
                        Page::Vault => self.vault_page(ui),
                        Page::Drive => self.drive_page(ui),
                    }

                    ui.add_space(35.0);
                });
        });
    }
}

fn unique_timestamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn original_filename(name: &str) -> String {
    name.strip_suffix(".fcloak").unwrap_or(name).to_string()
}

fn sanitize_temp_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn main() -> eframe::Result<()> {
    let app = match FcloakApp::new() {
        Ok(app) => app,

        Err(error) => {
            eprintln!("FCLOAK initialization failed: {error}");
            std::process::exit(1);
        }
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FCLOAK")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([1000.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "FCLOAK",
        options,
        Box::new(|_creation_context| Ok(Box::new(app))),
    )
}
