// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Starts the trade page: loads the SDK bundled beside it (./sdk, no CDN), runs its startup check
// on the embedded template, then mounts the page. If either fails the page shows why and derives
// nothing.
import init, * as sdk from "./sdk/index.js";
import { VALUE_CAP_SOMPI } from "./config.js";
import { mount, showStartupFailure } from "./app.js";

try {
  await init();
  sdk.templateCheck();
  await mount(document, sdk, { valueCapSompi: VALUE_CAP_SOMPI });
} catch (e) {
  showStartupFailure(document, e);
}
