import { bootstrap } from "./app.js";

bootstrap().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  const page = document.querySelector("#page");
  if (page) {
    const alert = document.createElement("p");
    alert.className = "error-banner";
    alert.setAttribute("role", "alert");
    alert.textContent = `Application startup failed: ${message}`;
    page.replaceChildren(alert);
  }
});
