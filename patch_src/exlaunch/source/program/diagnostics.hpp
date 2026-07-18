#pragma once

namespace ocoop::diagnostics {

// Profile-specific diagnostics startup. The public release implementation is
// intentionally empty; the private development profile may announce or install
// diagnostic facilities compiled from dev_private sources.
void Initialize();

}  // namespace ocoop::diagnostics
