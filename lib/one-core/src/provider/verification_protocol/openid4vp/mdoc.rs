use crate::provider::presentation_formatter::model::FormatPresentationCtx;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;

pub(crate) fn mdoc_presentation_context(
    handover: Handover,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    Ok(FormatPresentationCtx {
        mdoc_session_transcript: Some(to_cbor(&SessionTranscript {
            handover: Some(handover),
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
        })?),
        ..Default::default()
    })
}
