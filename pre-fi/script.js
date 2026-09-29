// Password visibility controls.
// Registration and login still work without JavaScript.
document.querySelectorAll("[data-toggle]").forEach((button) => {
    button.hidden = false;

    button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.toggle);
        const show = input.type === "password";
        const label = input.id === "confirm"
            ? "confirmation password"
            : "password";

        input.type = show ? "text" : "password";
        button.textContent = show ? "Hide" : "Show";
        button.setAttribute("aria-pressed", String(show));
        button.setAttribute(
            "aria-label",
            `${show ? "Hide" : "Show"} ${label}`
        );
    });
});

// Prevent accidental repeated submissions.
document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", () => {
        const button = form.querySelector('button[type="submit"]');

        if (button) {
            button.disabled = true;
            button.setAttribute("aria-busy", "true");
        }
    });
});

// Restore buttons when returning through browser history.
window.addEventListener("pageshow", () => {
    document.querySelectorAll('button[type="submit"]').forEach((button) => {
        button.disabled = false;
        button.removeAttribute("aria-busy");
    });
});

// Bring server-side validation errors to keyboard users.
document.getElementById("form-error")?.focus();