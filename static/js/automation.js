/* Recovery secrets are generated and downloaded locally, never posted to the CA. */
(() => {
  "use strict";
  const button = document.querySelector("[data-generate-recovery-key]");
  if (!button) return;
  const status = document.querySelector("[data-recovery-key-status]");
  const pem = (buffer, label) => {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `-----BEGIN ${label}-----\n${btoa(binary).match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
  };
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      if (!window.isSecureContext || !window.crypto?.subtle) {
        throw new Error("Key generation requires Web Crypto in a secure HTTPS browser context.");
      }
      status.textContent = "Generating your recovery key locally…";
      const pair = await crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true, ["encrypt", "decrypt"]);
      const publicDer = await crypto.subtle.exportKey("spki", pair.publicKey);
      const privateDer = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
      const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", publicDer)))
        .map(byte => byte.toString(16).padStart(2, "0")).join("");
      const blob = new Blob([pem(privateDer, "PRIVATE KEY")], { type: "application/x-pem-file" });
      const objectUrl = URL.createObjectURL(blob);
      const download = document.createElement("a");
      download.href = objectUrl;
      download.download = `pkimaster-recovery-${fingerprint.slice(0, 16)}.pem`;
      document.body.appendChild(download);
      download.click();
      download.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
      // Only the public key enters a named form field or the page DOM.
      document.querySelector("#backup-public-key").value = pem(publicDer, "PUBLIC KEY");
      document.querySelector("[data-recovery-fingerprint]").textContent = fingerprint;
      document.querySelector('[name="recovery_key_saved"]').checked = false;
      status.textContent = "Recovery-key download started. Verify the file was saved and store it securely outside this CA host, then confirm below and save the settings.";
      new Uint8Array(privateDer).fill(0);
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : "Recovery-key generation failed.";
    } finally {
      button.disabled = false;
    }
  });
})();
