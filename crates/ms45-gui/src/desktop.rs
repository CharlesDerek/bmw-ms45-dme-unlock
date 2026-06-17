use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use eframe::egui;
use ms45_core::{
    prepare_full_program, prepare_tune, verify_flash_mpc_match, verify_parameter_match,
    verify_program_match,
};

pub fn run() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 620.0]),
        ..Default::default()
    };

    eframe::run_native(
        "MS45 Flasher",
        options,
        Box::new(|_| Ok(Box::<Ms45App>::default())),
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))
}

#[derive(Default)]
struct Ms45App {
    tune_input: Option<PathBuf>,
    tune_output: Option<PathBuf>,
    sw_ref: String,
    external_input: Option<PathBuf>,
    mpc_input: Option<PathBuf>,
    external_output: Option<PathBuf>,
    mpc_output: Option<PathBuf>,
    hw_ref: String,
    status: String,
}

impl eframe::App for Ms45App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("MS45 Flasher");
            ui.add_space(6.0);
            ui.label("Offline binary preparation, validation, and signing. Live ECU flashing still requires a future Ediabas/PRG backend.");
            ui.add_space(14.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.columns(2, |columns| {
                    self.tune_panel(&mut columns[0]);
                    self.program_panel(&mut columns[1]);
                });

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    ui.strong("Status:");
                    ui.label(if self.status.is_empty() {
                        "Ready"
                    } else {
                        self.status.as_str()
                    });
                });
            });
        });
    }
}

impl Ms45App {
    fn tune_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("Tune");
            if path_row(ui, "Input", &self.tune_input) {
                self.tune_input = pick_file();
            }
            if path_row(ui, "Output", &self.tune_output) {
                self.tune_output = save_file("tune.prepared.bin");
            }
            ui.horizontal(|ui| {
                ui.label("SW ref");
                ui.text_edit_singleline(&mut self.sw_ref);
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Validate").clicked() {
                    self.status = self.validate_tune().unwrap_or_else(|err| err.to_string());
                }
                if ui.button("Prepare Tune").clicked() {
                    self.status = self.prepare_tune().unwrap_or_else(|err| err.to_string());
                }
            });
        });
    }

    fn program_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("Full Program");
            if path_row(ui, "External", &self.external_input) {
                self.external_input = pick_file();
            }
            if path_row(ui, "MPC", &self.mpc_input) {
                self.mpc_input = pick_file();
            }
            if path_row(ui, "External out", &self.external_output) {
                self.external_output = save_file("external_program.prepared.bin");
            }
            if path_row(ui, "MPC out", &self.mpc_output) {
                self.mpc_output = save_file("mpc_program.prepared.bin");
            }
            ui.horizontal(|ui| {
                ui.label("HW ref");
                ui.text_edit_singleline(&mut self.hw_ref);
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Validate").clicked() {
                    self.status = self
                        .validate_program()
                        .unwrap_or_else(|err| err.to_string());
                }
                if ui.button("Prepare Program").clicked() {
                    self.status = self.prepare_program().unwrap_or_else(|err| err.to_string());
                }
            });
        });
    }

    fn validate_tune(&self) -> Result<String> {
        let input = required(&self.tune_input, "select a tune input file")?;
        let bytes = read(input)?;
        if self.sw_ref.trim().is_empty() {
            return Ok(format!("Tune loaded: {} bytes", bytes.len()));
        }
        Ok(format!(
            "Tune/software reference match: {}",
            verify_parameter_match(&bytes, self.sw_ref.trim())?
        ))
    }

    fn prepare_tune(&self) -> Result<String> {
        let input = required(&self.tune_input, "select a tune input file")?;
        let output = required(&self.tune_output, "select a tune output file")?;
        let payload = prepare_tune(&read(input)?)?;
        std::fs::write(output, payload.data)
            .with_context(|| format!("failed to write {}", output.display()))?;
        Ok(format!("Prepared tune written to {}", output.display()))
    }

    fn validate_program(&self) -> Result<String> {
        let external = required(&self.external_input, "select an external flash file")?;
        let mpc = required(&self.mpc_input, "select an MPC file")?;
        let external_bytes = read(external)?;
        let mpc_bytes = read(mpc)?;
        let pair_match = verify_flash_mpc_match(&external_bytes, &mpc_bytes)?;
        if self.hw_ref.trim().is_empty() {
            return Ok(format!("External/MPC pair match: {pair_match}"));
        }
        Ok(format!(
            "Program/hardware reference match: {}; external/MPC pair match: {}",
            verify_program_match(&external_bytes, self.hw_ref.trim())?,
            pair_match
        ))
    }

    fn prepare_program(&self) -> Result<String> {
        let external = required(&self.external_input, "select an external flash file")?;
        let mpc = required(&self.mpc_input, "select an MPC file")?;
        let external_output = required(&self.external_output, "select an external output file")?;
        let mpc_output = required(&self.mpc_output, "select an MPC output file")?;
        let payload = prepare_full_program(&read(external)?, &read(mpc)?)?;
        std::fs::write(external_output, payload.external_program)
            .with_context(|| format!("failed to write {}", external_output.display()))?;
        std::fs::write(mpc_output, payload.mpc_program)
            .with_context(|| format!("failed to write {}", mpc_output.display()))?;
        Ok("Prepared program payloads written".to_string())
    }
}

fn path_row(ui: &mut egui::Ui, label: &str, path: &Option<PathBuf>) -> bool {
    ui.horizontal(|ui| {
        ui.label(label);
        let text = path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "No file selected".to_string());
        ui.add_sized([280.0, 22.0], egui::Label::new(text).truncate());
        ui.button("Browse").clicked()
    })
    .inner
}

fn pick_file() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("Binary", &["bin", "ori"])
        .pick_file()
}

fn save_file(name: &str) -> Option<PathBuf> {
    rfd::FileDialog::new().set_file_name(name).save_file()
}

fn required<'a>(path: &'a Option<PathBuf>, message: &str) -> Result<&'a Path> {
    path.as_deref()
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}
