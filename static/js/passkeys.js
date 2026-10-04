"use strict";

(() => {
  const decode = (value) => Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)),
    (character) => character.charCodeAt(0),
  );
  const encode = (value) => {
    const bytes = new Uint8Array(value);
    let binary = "";
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const csrf = () => document.querySelector("#passkey-csrf")?.value
    || document.querySelector('input[name="csrf_token"]')?.value || "";
  const post = async (url, values) => {
    const body = new URLSearchParams({ csrf_token: csrf(), ...values });
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
      body,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Passkey request failed.");
    return result;
  };
  const serialize = (credential, registration) => {
    const result = {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: encode(credential.response.clientDataJSON),
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    };
    if (registration) {
      result.response.attestationObject = encode(credential.response.attestationObject);
      if (credential.response.getTransports) result.response.transports = credential.response.getTransports();
    } else {
      result.response.authenticatorData = encode(credential.response.authenticatorData);
      result.response.signature = encode(credential.response.signature);
      if (credential.response.userHandle) result.response.userHandle = encode(credential.response.userHandle);
    }
    return result;
  };
  const show = (element, message) => {
    const target = document.querySelector("[data-passkey-message]");
    if (target) target.textContent = message;
    if (element) element.disabled = false;
  };

  document.querySelectorAll("[data-passkey-register]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        if (!window.PublicKeyCredential || !navigator.credentials?.create) throw new Error("This browser does not support passkeys.");
        const options = await post(button.dataset.beginUrl, {});
        options.challenge = decode(options.challenge);
        options.user.id = decode(options.user.id);
        (options.excludeCredentials || []).forEach((item) => { item.id = decode(item.id); });
        const credential = await navigator.credentials.create({ publicKey: options });
        if (!credential) throw new Error("Passkey registration was cancelled.");
        const result = await post(button.dataset.completeUrl, {
          credential_json: JSON.stringify(serialize(credential, true)),
          label: document.querySelector('input[name="label"]')?.value || "",
          totp_code: document.querySelector('input[name="totp_code"]')?.value || "",
        });
        show(button, result.message || "Passkey registered.");
        window.location.reload();
      } catch (error) {
        show(button, error.message || "Passkey registration failed.");
      }
    });
  });

  document.querySelectorAll("[data-passkey-auth]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      const message = document.querySelector("[data-passkey-message]");
      if (message) message.textContent = "Waiting for your passkey…";
      try {
        if (!window.PublicKeyCredential || !navigator.credentials?.get) throw new Error("This browser does not support passkeys.");
        const options = await post(button.dataset.beginUrl, {});
        options.challenge = decode(options.challenge);
        (options.allowCredentials || []).forEach((item) => { item.id = decode(item.id); });
        const credential = await navigator.credentials.get({ publicKey: options });
        if (!credential) throw new Error("Passkey sign-in was cancelled.");
        const result = await post(button.dataset.completeUrl, {
          credential_json: JSON.stringify(serialize(credential, false)),
        });
        window.location.assign(result.redirect);
      } catch (error) {
        show(button, error.message || "Passkey verification failed.");
      }
    });
  });
})();
