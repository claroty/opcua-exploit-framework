from datetime import datetime, timedelta, tzinfo
from calendar import timegm
from construct import * # construct==2.10.56

EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000

ZERO = timedelta(0)
HOUR = timedelta(hours=1)


class UTC(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


utc = UTC()


def dt_to_filetime(dt):
    if (dt.tzinfo is None) or (dt.tzinfo.utcoffset(dt) is None):
        dt = dt.replace(tzinfo=utc)
    return EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)


def get_real_time(dt):
    us = dt / 10
    return datetime(1601, 1, 1) + timedelta(microseconds=us)


OPC_STRING = Struct(
    "str_length" / Int32ul,
    "str" / If(this.str_length != 0xffffffff, PaddedString(this.str_length, "utf8"))
)

OPC_BYTES = Struct(
    "bytes_length" / Int32ul,
    "bytes" / IfThenElse(this.bytes_length == 0xffffffff, Bytes(0), Bytes(this.bytes_length)))

ARRAY_OF_STRINGS = Struct(
    "array_size" / Int32ul,
    "string_array" / If(this.array_size != 0xffffffff, Array(this.array_size, OPC_STRING))
)
########################################################################################################################
#################################                     NAMESPACE MASKS          #########################################
########################################################################################################################
SIZE_LENGTH = Struct(
    "namespace_index" / Int16ul,
    "item" / Int32ul
)
OPAQUE = Struct(
    "namespace_index" / Int16ul,
    "item" / OPC_BYTES
)

FOUR_BYTE = Struct(
    "namespace_index" / Int8ul,
    "item" / Int16ul
)

GUID = Struct(
    "namespace_index" / Int16ul,
    "item" / Bytes(16)
)
ONLY_ITEM = Struct(
    "namespace_index" / Pass,
    "item" / Int8ul
)

TEST_ITEM = Struct(
    "namespace_index" / Int16ul,
    "item" / OPC_STRING
)

SECURITY_TOKEN = Struct(
    "channel_id" / Int32ul,
    "token_id" / Int32ul,
    "token_timestamp" / Int64ul,
    "token_revised_lifetime" / Int32ul
)

LOCALIZED_TEXT = Struct(
        "encoding_mask" / BitStruct(
            "na1" / Nibble,
            "na2" / Flag,
            "na3" / Flag,
            "has_has_text" / Flag,
            "has_locale_info" / Flag,
        ),
        "text" / If(this.encoding_mask.has_has_text, OPC_STRING),
        "locale" / If(this.encoding_mask.has_locale_info, OPC_STRING)
)

OBJECT = Struct(
    "encoding_mask" / BitStruct(
        "has_namespace_uri" / Flag,
        "has_server_index" / Flag,
        "unk1" / Flag,
        "unk2" / Flag,
        "arbitrary_length" / Nibble
),
    "identifier_numeric" / Switch(this.encoding_mask.arbitrary_length,
                                  {0: ONLY_ITEM,
                                   1: FOUR_BYTE,
                                   3: TEST_ITEM,
                                   2: SIZE_LENGTH,
                                   4: GUID,
                                   5: OPAQUE}
                                  )
)

OBJECT_HEADER = Struct(
    "main_object" / OBJECT,
    "timestamp" / Int64ul,
    "request_handle" / Int32ul,
    # bitmap
    "return_diagnostics" / Int32ul,
    "audit_entry_id" / OPC_STRING,
    "timeout_hint" / Int32ul,
    "extension_object" / OBJECT,
)
########################################################################################################################
########################################                OPEN             ###############################################
########################################################################################################################
OPEN_SECURE_CHANNEL_REQUEST = Struct(
    "authentication_token" / OBJECT_HEADER,
    "encoding_mask" / Int8ul,
    "client_protocol_version" / Int32ul,
    "security_request_type" / Int32ul,
    "message_security_mode" / Int32ul,
    "unk" / Int32ul,
    "has_nonce" / Peek(GreedyBytes),

    "client_nonce" / If(lambda x: len(x.has_nonce) > 4,  Int8ul),
    "requested_lifetime" / Int32ul
)

OPEN_SECURE_CHANNEL_RESPONSE = Struct(
    # OpenSecureChannelResponse:
    "timestamp" / Int64ul,
    "request_handle" / Int32ul,
    "service_results" / Int32ul,
    "service_diagnostics" / Int8ul,
    "string_table_size" / Int32ul,
    "string_array" / If(this.string_table_size != 0xffffffff, Array(lambda x: x.string_table_size, OPC_STRING)),
    "additional_header_type_id" / Int16ul,
    "additional_header_encoding_mask" / Int8ul,
    "server_protocol_version" / Int32ul,
    "security_token" / SECURITY_TOKEN,
    "server_nonce" / OPC_BYTES
)
########################################################################################################################
########################################                CREATE           ###############################################
########################################################################################################################
CREATE_SESSION_REQUEST = Struct(
    "authenticationobject" / OBJECT_HEADER,
    "binary_or_xml" / Int8ul,
    "application_uri" / OPC_STRING,
    "product_uri" / OPC_STRING,
    "localized_text" / LOCALIZED_TEXT,
    "application_type" / Int32ul,
    "gateway_server_uri" / OPC_STRING,
    "discovery_profile_uri" / OPC_STRING,
    "num_of_discovery_urls" / Int32ul,
    "discovery_urls" / If(this.num_of_discovery_urls != 0xffffffff, Array(lambda x: x.num_of_discovery_urls, OPC_STRING)),
    "server_uri" / OPC_STRING,
    "enspoint_url" / OPC_STRING,
    "session_name" / OPC_STRING,
    "client_nonce_size" / Int32ul,
    "client_nonce" / If(this.client_nonce_size != 0xffffffff, Bytes(this.client_nonce_size)),
    "client_certificate" / OPC_BYTES,
    # "uukn" / Int32ul,
    "request_session_timeout" / Float64l,
    "max_response_message_size" / Int32ul,
)

CREATE_SESSION_RESPONSE = Struct(
    "timestamp" / Int64ul,
    "request_handler" / Int32ul,
    "service_results" / Int32ul,
    "service_diagnostics_encoding_mask" / Int8ul,
    "string_array" / ARRAY_OF_STRINGS,
    "ext_obj" / OBJECT,
    "encoding_mask" / Int8ul,
    "session_id" / OBJECT,
    "auth_token" / OBJECT
)
ACTIVATE_REQUEST = Struct(
    "auth_token" / OBJECT_HEADER,
    "encoding_mask" / Int8ul,
    "algo" / OPC_STRING,
    "signature" / OPC_BYTES,
    "client_cert_array_size" / Int32ul,
    "client_cert_array" / If(this.client_cert_array_size != 0xffffffff, Array(this.client_cert_array_size, OPC_BYTES)),
    "local_ids_array_size" / Int32ul,
    "local_ids_array" / If(this.client_cert_array_size != 0xffffffff, Array(this.local_ids_array_size, OPC_STRING)),
    "user_id_token" / OBJECT,
    "encoding_mask2" / Int8ul,
    "unk" / Int32ul,
    "policy_id" / OPC_STRING,
    "sign_algo" / OPC_STRING,
    "sign_sig" / OPC_BYTES
)




CLOSE_SESSION_REQUEST = Struct(
    "authentication_token" / OBJECT_HEADER,
)
########################################################################################################################
########################################                BROWSE           ###############################################
########################################################################################################################
BROWSE_DESCRIPTION = Struct(
    "node_id" / OBJECT,
    "browse_direction" / Int32ul,
    "reference_node_id" / OBJECT,
    "include_subtypes" / Int8ul,

    "node_class_mask" / BitStruct(
        "mask_view_type" / Flag,
        "mask_data_type" / Flag,
        "mask_reference_type" / Flag,
        "mask_variable_type" / Flag,
        "mask_object_type" / Flag,
        "mask_method" / Flag,
        "mask_variable" / Flag,
        "mask_object" / Flag,
        "mask_un_0" / Nibble,
        "mask_un_1" / Nibble,


        ),
    "node_class_unused" / Int16ul,

    "result_mask" / BitStruct(
        "res_un_0" / Flag,
        "res_un_1" / Flag,
        "res_type_definition" / Flag,
        "res_display_name" / Flag,
        "res_browse_name" / Flag,
        "res_node_class" / Flag,
        "res_is_forward" / Flag,
        "res_reference_type" / Flag,
    ),
    "result_mask_not_used" / Int16ul,

)
BROWSE_REQUEST = Struct(
    "auth_token" / OBJECT_HEADER,
    "encoding_mask" / Int8ul,
    "view" / OBJECT,
    "timestamp" / Int64ul,
    "view_version" / Int32ul,
    "requested_max_references_per_node" / Int32ul,
    "array_size" / Int32ul,
    "browse_descriptions" / Array(lambda x: x.array_size, BROWSE_DESCRIPTION)
)
BROWSE_NAME = Struct(
    "browse_id" / Int16ul,
    "browse_name" / OPC_STRING
)

REFERENCE_DESCRIPTION = Struct(
    "reference_id" / OBJECT,
    "is_forward" / Int8ul,
    "expanded_node_id" / OBJECT,
    "browse_name" / BROWSE_NAME,
    "display_name_mask" / BitStruct(
        "unknown_1" / Nibble,
        "unknown_2" / Flag,
        "unknown_3" / Flag,
        "has_text" / Flag,
        "has_locale_information" / Flag,
    ),
    "display_name" / If(lambda x: x.display_name_mask.has_text, OPC_STRING),
    "node_class" / Int32ul,
    "type_definition" / OBJECT


)
BROWSE_RESULT_ITEM = Struct(
    "status_code" / Int32ul,
    "continuation_point" / OPC_BYTES,
    "references_size" / Int32ul,
    "references" / Array(lambda x: x.references_size, REFERENCE_DESCRIPTION)
)

BROWSE_RESPONSE = Struct(
    "timestamp" / Int64ul,
    "request_handler" / Int32ul,
    "service_results" / Int32ul,
    "service_diagnostics_encoding_mask" / Int8ul,
    "string_array" / ARRAY_OF_STRINGS,
    "ext_obj" / OBJECT,
    "encoding_mask" / Int8ul,
    "array_size" / Int32ul,
    "browse_results" / Array(lambda x: x.array_size, BROWSE_RESULT_ITEM)

)

ITEM_TO_MONITOR = Struct(
    "node_id" / OBJECT,
    "attribute_id" / Int32ul,
    "index_range" / OPC_STRING,
    "data_encoding" / BROWSE_NAME,
)

REQUESTED_PARAMETERS = Struct(
    "client_handle" / Int32ul,
    "sampling_interval" / Int64ul,
    "filter" / OBJECT,
    "encoding_mask" / Int8ul,
    "queue_size" / Int32ul,
    "discard_oldest" / Int8ul
)

MONITORED_ITEM_FOR_CREATE_REQUES = Struct(
    "item_to_monitor" / ITEM_TO_MONITOR,
    "monitoring_mode" / Int32ul,
    "requested_parameters" / REQUESTED_PARAMETERS
)

########################################################################################################################
########################################            ENCODABLES           ###############################################
########################################################################################################################
ENCODEABLE_OBJECT = Struct(
    "node_id_encoding_mask" / Int8ul,
    "node_id_namespace_index" / Int8ul,
    "node_id_identifier_numeric" / Int16ul,
    "object" / Switch(this.node_id_identifier_numeric,
                      {
                          446: OPEN_SECURE_CHANNEL_REQUEST,
                          449: OPEN_SECURE_CHANNEL_RESPONSE,
                          461: CREATE_SESSION_REQUEST,
                          464: CREATE_SESSION_RESPONSE,
                          467: ACTIVATE_REQUEST,
                          473: CLOSE_SESSION_REQUEST,
                          527: BROWSE_REQUEST,
                          530: BROWSE_RESPONSE
                      })
)

OPEN_REQUEST = Struct(
    "secure_channel_id" / Int32ul,
    # http://opcfoundation.org/UA/SecurityPolicy#None
    "securit_policy_uri" / OPC_STRING,
    # ffffff
    "sender_certificate" / OPC_STRING,
    "reciever_certificate_thumbprint" / OPC_STRING,
    "sequence_number" / Int32ul,
    "request_id_number" / Int32ul,

    # encodable_object:
    "object" / ENCODEABLE_OBJECT
)

HELLO_REQUEST = Struct(
    "version" / Int32ul,
    "receive_buffer_size" / Int32ul,
    "send_buffer_size" / Int32ul,
    "max_message_size" / Int32ul,
    "max_chunk_count" / Int32ul
)
########################################################################################################################
########################################            HEADERS              ###############################################
########################################################################################################################
OPEN = Struct(
    "secure_channel_id" / Int32ul,
    # http://opcfoundation.org/UA/SecurityPolicy#None
    "securit_policy_uri" / OPC_STRING,
    # ffffff
    "sender_certificate" / OPC_STRING,
    "reciever_certificate_thumbprint" / OPC_STRING,
    "sequence_number" / Int32ul,
    "request_id_number" / Int32ul,

    # encodable_object:
    "object" / ENCODEABLE_OBJECT
)

MSG = Struct(
    "secure_channel_id" / Int32ul,
    "security_token_id" / Int32ul,
    "security_sequence_number" / Int32ul,
    "security_request_idr" / Int32ul,
    "object" / ENCODEABLE_OBJECT
)
HELLO = Struct(
    "version" / Int32ul,
    "receive_buffer_size" / Int32ul,
    "send_buffer_size" / Int32ul,
    "max_message_size" / Int32ul,
    "max_chunk_count" / Int32ul
)

HELLO_MSG = Struct(
    "hello_header" / HELLO,
    # opc.tcp://ip:port
    "endpoint_url" / OPC_STRING)

OPCUA_MESSAGE = Struct(
    "message_type" / PaddedString(3, "utf8"),
    "chunk_type" / PaddedString(1, "utf8"),
    "message_size" / Int32ul,
    "opc_data" / Switch(this.message_type,
                        {"HEL": HELLO_MSG,
                         "ACK": HELLO,
                         "OPN": OPEN,
                         "MSG": MSG}),
    "leftover" / GreedyBytes
)