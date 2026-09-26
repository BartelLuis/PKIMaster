"use strict";

document.documentElement.classList.add("has-js");
const navigation = document.getElementById("console-navigation");
const menuButton = document.querySelector(".menu-button");
if (navigation && menuButton) {
  const narrowViewport = window.matchMedia("(max-width: 680px)");
  const updateNavigationFocus = () => {
    navigation.inert = narrowViewport.matches && !navigation.classList.contains("is-open");
  };
  const closeNavigation = () => {
    navigation.classList.remove("is-open");
    menuButton.setAttribute("aria-expanded", "false");
    updateNavigationFocus();
  };
  menuButton.addEventListener("click", () => {
    const expanded = menuButton.getAttribute("aria-expanded") !== "true";
    navigation.classList.toggle("is-open", expanded);
    menuButton.setAttribute("aria-expanded", String(expanded));
    updateNavigationFocus();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && navigation.classList.contains("is-open")) {
      closeNavigation();
      menuButton.focus();
    }
  });
  document.addEventListener("click", (event) => {
    if (!navigation.contains(event.target) && !menuButton.contains(event.target)) closeNavigation();
  });
  narrowViewport.addEventListener("change", closeNavigation);
  updateNavigationFocus();
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
