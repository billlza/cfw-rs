import { startStartupGuard } from "./startup-guard.js";
// This entry point must load before, and independently of, the dashboard bundle.
// A module evaluation failure cannot be caught by bootstrap().catch().
startStartupGuard();
