// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// What this page is configured with. The per-trade value cap is in sompi, a decimal string. The
// SDK refuses a cap above its own default (10 KAS, decision D4) and the page has no way to lift
// the cap, so this can only be lowered.
export const VALUE_CAP_SOMPI = "1000000000";
