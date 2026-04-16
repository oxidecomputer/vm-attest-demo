// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};

mod test_data;

fn main() -> Result<()> {
    test_data::generate().context("generate mock data for testing")?;

    Ok(())
}
