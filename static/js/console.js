"use strict";

// Executed before CSS: restore the theme before the first paint, without inline JS.
(() => {
  const root = document.documentElement;
  const storageKey = "pkimaster.theme";
  const choices = new Set(["light", "dark", "system"]);
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "light";
  try {
    const saved = window.localStorage.getItem(storageKey);
    if (choices.has(saved)) preference = saved;
  } catch { /* The switch still works when browser storage is unavailable. */ }
  const applyTheme = () => {
    root.dataset.theme = preference === "system" ? (systemTheme.matches ? "dark" : "light") : preference;
    document.querySelectorAll("[data-theme-select]").forEach((select) => { select.value = preference; });
  };
  root.classList.add("has-js");
  applyTheme();
  systemTheme.addEventListener("change", () => { if (preference === "system") applyTheme(); });
  window.addEventListener("storage", (event) => {
    if (event.key !== storageKey && event.key !== null) return;
    preference = choices.has(event.newValue) ? event.newValue : "light";
    applyTheme();
  });

  const initialize = () => {
    document.querySelectorAll("[data-theme-select]").forEach((select) => {
      select.value = preference;
      select.closest(".theme-switcher").hidden = false;
      select.addEventListener("change", () => {
        preference = choices.has(select.value) ? select.value : "light";
        applyTheme();
        try { window.localStorage.setItem(storageKey, preference); } catch { /* Optional persistence. */ }
      });
    });

    const navigation = document.getElementById("console-navigation");
    const menuButton = document.querySelector(".menu-button");
    const closeButton = document.querySelector(".navigation-close");
    const backdrop = document.querySelector(".navigation-backdrop");
    const shell = document.querySelector(".app-shell");
    if (navigation && menuButton && closeButton && backdrop && shell) {
      const narrowViewport = window.matchMedia("(max-width: 1024px)");
      const isOpen = () => navigation.classList.contains("is-open");
      const closeNavigation = (restoreFocus = false) => {
        navigation.classList.remove("is-open");
        navigation.removeAttribute("role");
        navigation.removeAttribute("aria-modal");
        navigation.inert = narrowViewport.matches;
        menuButton.setAttribute("aria-expanded", "false");
        backdrop.hidden = true;
        shell.inert = false;
        document.body.classList.remove("navigation-open");
        if (restoreFocus && narrowViewport.matches) menuButton.focus();
      };
      const openNavigation = () => {
        if (!narrowViewport.matches) return;
        navigation.inert = false;
        navigation.classList.add("is-open");
        navigation.setAttribute("role", "dialog");
        navigation.setAttribute("aria-modal", "true");
        menuButton.setAttribute("aria-expanded", "true");
        backdrop.hidden = false;
        shell.inert = true;
        document.body.classList.add("navigation-open");
        closeButton.focus();
      };
      menuButton.addEventListener("click", () => { if (isOpen()) closeNavigation(true); else openNavigation(); });
      closeButton.addEventListener("click", () => closeNavigation(true));
      backdrop.addEventListener("click", () => closeNavigation(true));
      document.addEventListener("keydown", (event) => {
        if (!isOpen()) return;
        if (event.key === "Escape") {
          event.preventDefault();
          closeNavigation(true);
        } else if (event.key === "Tab") {
          const focusable = [...navigation.querySelectorAll("a[href],button:not([disabled]),select,input:not([type=hidden]):not([disabled]),[tabindex='0']")]
            .filter((element) => element.getClientRects().length);
          const first = focusable[0];
          const last = focusable[focusable.length - 1];
          if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
          else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
        }
      });
      narrowViewport.addEventListener("change", () => closeNavigation());
      closeNavigation();
    }

    const accountSource = document.querySelector("[data-account-source]");
    if (accountSource) {
      const updateAccountFields = () => {
        const external = accountSource.value !== "local";
        document.querySelectorAll("[data-local-account]").forEach((field) => {
          field.hidden = external;
          field.querySelectorAll("input").forEach((input) => { input.required = !external; input.disabled = external; });
        });
        document.querySelectorAll("[data-external-account]").forEach((field) => {
          field.hidden = !external;
          field.querySelectorAll("input").forEach((input) => { input.required = external; input.disabled = !external; });
        });
      };
      accountSource.addEventListener("change", updateAccountFields);
      updateAccountFields();
    }
    document.querySelectorAll("select[data-certificate-template]").forEach((select) => {
      const form = select.closest("form");
      const validity = form?.querySelector("input[name=validity_days]");
      const profile = form?.querySelector("input[type=hidden][name=profile]");
      if (!validity) return;
      const positive = (value) => { const number = Number(value); return Number.isFinite(number) && number > 0 ? number : null; };
      const installationMax = positive(validity.dataset.installationMax) || positive(validity.max);
      const updateTemplate = (changed) => {
        const option = select.selectedOptions[0];
        if (!option) return;
        const limits = [installationMax, positive(option.dataset.maxDays)].filter((value) => value !== null);
        const maximum = limits.length ? Math.min(...limits) : null;
        if (maximum) validity.max = String(maximum);
        if (changed) {
          const defaults = [positive(option.dataset.defaultDays), maximum].filter((value) => value !== null);
          if (defaults.length) validity.value = String(Math.min(...defaults));
        } else if (maximum && positive(validity.value) > maximum) {
          validity.value = String(maximum);
        }
        if (profile && option.dataset.profile) profile.value = option.dataset.profile;
      };
      select.addEventListener("change", () => updateTemplate(true));
      updateTemplate(false);
    });
    document.querySelectorAll(".table-scroll, .table-wrap").forEach((wrapper) => {
      wrapper.tabIndex = 0;
      wrapper.setAttribute("role", "region");
      if (!wrapper.hasAttribute("aria-label") && !wrapper.hasAttribute("aria-labelledby")) {
        const heading = wrapper.closest(".card")?.querySelector("h2,h3");
        wrapper.setAttribute("aria-label", heading ? heading.textContent.trim() + " table" : "Scrollable table");
      }
    });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize, {once: true});
  else initialize();
})();
