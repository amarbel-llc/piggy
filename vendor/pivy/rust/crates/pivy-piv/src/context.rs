use pcsc::{Context, Scope};

use crate::error::PivError;

pub struct PivContext {
    ctx: Context,
}

impl PivContext {
    pub fn new() -> Result<Self, PivError> {
        let ctx = Context::establish(Scope::System)?;
        Ok(Self { ctx })
    }

    pub fn list_readers(&self) -> Result<Vec<String>, PivError> {
        let mut buf = vec![0u8; 4096];
        let readers = self.ctx.list_readers(&mut buf)?;
        Ok(readers
            .map(|r| r.to_string_lossy().into_owned())
            .collect())
    }

    pub fn pcsc_context(&self) -> &Context {
        &self.ctx
    }
}
