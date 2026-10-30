//! `AuthStateReader` of the NetworkManager engine: the pending dynamic challenge (CRV1) from the secret agent
//! (L-b Task 21), by the run's NM connection UUID.

use crate::lin::nm::engine::Engine;
use macvpn_core::mfa::AuthUIState;
use macvpn_platform_api::AuthStateReader;
use uuid::Uuid;

impl AuthStateReader for Engine {
    fn read(&self, id: &Uuid) -> Option<AuthUIState> {
        let agent = self.helper.agent.get()?;
        let nm_uuid = {
            let runs = self.helper.runs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            runs.by_id.get(id)?.nm_uuid.clone()
        };
        agent.challenge(&nm_uuid)
    }
}
