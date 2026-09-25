use steam_vent_proto_common::protobuf::{self, CodedInputStream, Message, SpecialFields};
use steam_vent_proto_common::{GCHandshake, RpcMessage, RpcMessageWithKind};
use steam_vent_proto_steam::steammessages_clientserver_login::CMsgClientHello;

use crate::game_coordinator::GCMsgKind;

/// A generic handshake implementation for connecting to game coordinators.
///
/// Game-specific handshake implementation can generally be found in the game-specific protobuf packages.
/// Those can be more reliable for establishing a connection.
pub struct GenericGCHandshake {
    pub app_id: u32,
}

impl GenericGCHandshake {
    #[must_use]
    pub fn new(app_id: u32) -> Self {
        Self { app_id }
    }
}

impl GCHandshake for GenericGCHandshake {
    type Hello = CMsgClientHello;

    type Welcome = GenericCMsgClientWelcome;

    fn app_id(&self) -> u32 {
        self.app_id
    }

    fn hello(&self) -> Self::Hello {
        CMsgClientHello::default()
    }
}

#[derive(PartialEq, Clone, Default, Debug)]
pub struct GenericCMsgClientWelcome {
    pub special_fields: SpecialFields,
}

impl Message for GenericCMsgClientWelcome {
    const NAME: &'static str = "CMsgClientWelcome";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut CodedInputStream<'_>) -> protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            protobuf::rt::read_unknown_or_skip_group(
                tag,
                is,
                self.special_fields.mut_unknown_fields(),
            )?;
        }
        Ok(())
    }

    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        my_size += protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(
        &self,
        os: &mut protobuf::CodedOutputStream<'_>,
    ) -> protobuf::Result<()> {
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> GenericCMsgClientWelcome {
        GenericCMsgClientWelcome::default()
    }

    fn clear(&mut self) {
        self.special_fields.clear();
    }

    fn default_instance() -> &'static GenericCMsgClientWelcome {
        static INSTANCE: GenericCMsgClientWelcome = GenericCMsgClientWelcome {
            special_fields: SpecialFields::new(),
        };
        &INSTANCE
    }
}

impl RpcMessage for GenericCMsgClientWelcome {
    fn parse(reader: &mut dyn std::io::Read) -> protobuf::Result<Self> {
        protobuf::Message::parse_from_reader(reader)
    }
    fn write(&self, writer: &mut dyn std::io::Write) -> protobuf::Result<()> {
        self.write_to_writer(writer)
    }
    fn encode_size(&self) -> usize {
        self.compute_size() as usize
    }
}

impl RpcMessageWithKind for GenericCMsgClientWelcome {
    type KindEnum = GCMsgKind;

    const KIND: Self::KindEnum = GCMsgKind::k_EMsgGCClientWelcome;
}
