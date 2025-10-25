window.addEventListener("DOMContentLoaded", () => {
  const flashes = document.querySelectorAll("#flash-root .flash");
  flashes.forEach((el, idx) => {
    const delay = 3500 + idx * 200;
    setTimeout(() => {
      el.classList.add("flash-hide");
      setTimeout(() => el.remove(), 300);
    }, delay);
  });
});

document.addEventListener("click", (e) => {
  if (e.target && e.target.closest("#flash-root .btn-close")) {
    const card = e.target.closest(".flash");
    if (card) {
      card.classList.add("flash-hide");
      setTimeout(() => card.remove(), 150);
    }
  }
});

document.addEventListener("DOMContentLoaded", function () {
  function bindToggle(checkboxId, inputName) {
    const cb = document.getElementById(checkboxId);
    const input = document.querySelector(`input[name="${inputName}"]`);
    if (!cb || !input) return;
    const apply = () => {
      input.disabled = !cb.checked;
      if (!cb.checked) input.value = "";
    };
    cb.addEventListener("change", apply);
    apply();
  }
  bindToggle("algAES", "key_AES");
  bindToggle("algDES", "key_DES");
  bindToggle("algRC4", "key_RC4");
});

const modalEl = document.getElementById("shareModal");
const filenameInput = document.getElementById("shareFilename");
const form = document.getElementById("shareForm");
const modal = modalEl
  ? new bootstrap.Modal(modalEl, { backdrop: true, keyboard: true })
  : null;

document.querySelectorAll(".btn-share").forEach((btn) => {
  btn.addEventListener("click", function (e) {
    e.preventDefault();
    const actionUrl = this.getAttribute("href");
    const filename = this.getAttribute("data-filename") || "";
    if (form) form.setAttribute("action", actionUrl);
    if (filenameInput) filenameInput.value = filename;
    if (modal) modal.show();
  });
});

const decryptModalEl = document.getElementById("decryptModal");
const decryptFilenameInput = document.getElementById("decryptFilename");
const decryptKeyInput = document.getElementById("decryptKey");
const decryptForm = document.getElementById("decryptForm");
const decryptModal = decryptModalEl
  ? new bootstrap.Modal(decryptModalEl, { backdrop: true, keyboard: true })
  : null;

document.querySelectorAll(".btn-decrypt").forEach((btn) => {
  btn.addEventListener("click", function (e) {
    e.preventDefault();
    const actionUrl = this.getAttribute("href");
    const filename = this.getAttribute("data-filename") || "";
    const algorithm = this.getAttribute("data-algorithm") || "";

    if (decryptForm) decryptForm.setAttribute("action", actionUrl);
    if (decryptFilenameInput)
      decryptFilenameInput.value = filename + " (" + algorithm + ")";
    if (decryptKeyInput) decryptKeyInput.value = "";
    if (decryptModal) decryptModal.show();
  });
});

if (decryptModalEl) {
  decryptModalEl.addEventListener("hidden.bs.modal", function () {
    if (decryptForm) decryptForm.reset();
    if (decryptKeyInput) decryptKeyInput.value = "";
  });
}

if (modalEl) {
  modalEl.addEventListener("hidden.bs.modal", function () {
    if (form) form.reset();
  });
}
