const statusEl = document.querySelector("#status");
const tuneForm = document.querySelector("#tune-form");
const programForm = document.querySelector("#program-form");

tuneForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await downloadFromForm("/api/prepare-tune", tuneForm, "tune.prepared.bin");
});

programForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await downloadFromForm("/api/prepare-program", programForm, "ms45-program-payload.zip");
});

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
