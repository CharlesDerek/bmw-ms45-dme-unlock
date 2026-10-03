const statusEl = document.querySelector("#status");
const tuneForm = document.querySelector("#tune-form");
const programForm = document.querySelector("#program-form");
const flashPlanForm = document.querySelector("#flash-plan-form");

tuneForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await downloadFromForm("/api/prepare-tune", tuneForm, "tune.prepared.bin");
});

programForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await downloadFromForm("/api/prepare-program", programForm, "ms45-program-payload.zip");
});

flashPlanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true);
  setStatus("Verifying flash plan...");
  try {
    const response = await fetch("/api/inspect-flash-plan", {
      method: "POST",
      body: new FormData(flashPlanForm),
    });
    const inspection = await response.json();
    if (!response.ok) throw new Error(inspection.error || "Flash plan inspection failed");
    setStatus(formatInspection(inspection));
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    setBusy(false);
  }
});

function formatInspection(inspection) {
  const identity = inspection.approved_identity;
  const lines = [
    "Signature: verified",
    `ECU: ${identity.variant} / HW ${identity.hardware_reference} / SW ${identity.software_reference}`,
    `Signature target: ${inspection.signature_target}`,
    `Block size: ${inspection.block_size} bytes`,
    `Total write: ${inspection.total_bytes} bytes`,
    "Erase ranges:",
    ...inspection.erase_ranges.map(formatRange),
    "Write ranges:",
    ...inspection.write_ranges.map(formatRange),
  ];
  return lines.join("\n");
}

function formatRange(range) {
  const start = range.start.toString(16).padStart(8, "0");
  const end = range.end_exclusive.toString(16).padStart(8, "0");
  return `  ${range.region} 0x${start}..0x${end} (${range.length} bytes)`;
}

document.querySelector("[data-action='validate-tune']").addEventListener("click", async () => {
  const data = new FormData();
  const file = tuneForm.elements.input.files[0];
  if (file) data.append("tune", file);
  data.append("sw_ref", tuneForm.elements.sw_ref.value);
  await validate(data);
});

document.querySelector("[data-action='validate-program']").addEventListener("click", async () => {
  const data = new FormData(programForm);
  await validate(data);
});

async function validate(data) {
  setBusy(true);
  setStatus("Validating...");
  try {
    const response = await fetch("/api/validate", { method: "POST", body: data });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Validation failed");
    setStatus(payload.checks.map((check) => `${check.name}: ${check.ok}`).join("\n"));
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    setBusy(false);
  }
}

async function downloadFromForm(url, form, fallbackName) {
  setBusy(true);
  setStatus("Preparing payload...");
  try {
    const response = await fetch(url, { method: "POST", body: new FormData(form) });
    if (!response.ok) {
      const payload = await response.json();
      throw new Error(payload.error || "Preparation failed");
    }
    const blob = await response.blob();
    const filename = filenameFromDisposition(response.headers.get("content-disposition")) || fallbackName;
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(href);
    setStatus(`Prepared ${filename}`);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    setBusy(false);
  }
}

function filenameFromDisposition(header) {
  if (!header) return null;
  const match = header.match(/filename="([^"]+)"/);
  return match ? match[1] : null;
}

function setBusy(busy) {
  document.querySelectorAll("button").forEach((button) => {
    button.disabled = busy;
  });
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}
