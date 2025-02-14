# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: scanoss/api/semgrep/v2/scanoss-semgrep.proto
"""Generated protocol buffer code."""

from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from scanoss.api.common.v2 import scanoss_common_pb2 as scanoss_dot_api_dot_common_dot_v2_dot_scanoss__common__pb2
from google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2
from protoc_gen_swagger.options import annotations_pb2 as protoc__gen__swagger_dot_options_dot_annotations__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n,scanoss/api/semgrep/v2/scanoss-semgrep.proto\x12\x16scanoss.api.semgrep.v2\x1a*scanoss/api/common/v2/scanoss-common.proto\x1a\x1cgoogle/api/annotations.proto\x1a,protoc-gen-swagger/options/annotations.proto"\x96\x03\n\x0fSemgrepResponse\x12<\n\x05purls\x18\x01 \x03(\x0b\x32-.scanoss.api.semgrep.v2.SemgrepResponse.Purls\x12\x35\n\x06status\x18\x02 \x01(\x0b\x32%.scanoss.api.common.v2.StatusResponse\x1a\x43\n\x05Issue\x12\x0e\n\x06ruleID\x18\x01 \x01(\t\x12\x0c\n\x04\x66rom\x18\x02 \x01(\t\x12\n\n\x02to\x18\x03 \x01(\t\x12\x10\n\x08severity\x18\x04 \x01(\t\x1a\x64\n\x04\x46ile\x12\x0f\n\x07\x66ileMD5\x18\x01 \x01(\t\x12\x0c\n\x04path\x18\x02 \x01(\t\x12=\n\x06issues\x18\x03 \x03(\x0b\x32-.scanoss.api.semgrep.v2.SemgrepResponse.Issue\x1a\x63\n\x05Purls\x12\x0c\n\x04purl\x18\x01 \x01(\t\x12\x0f\n\x07version\x18\x02 \x01(\t\x12;\n\x05\x66iles\x18\x03 \x03(\x0b\x32,.scanoss.api.semgrep.v2.SemgrepResponse.File2\xf8\x01\n\x07Semgrep\x12p\n\x04\x45\x63ho\x12".scanoss.api.common.v2.EchoRequest\x1a#.scanoss.api.common.v2.EchoResponse"\x1f\x82\xd3\xe4\x93\x02\x19"\x14/api/v2/semgrep/echo:\x01*\x12{\n\tGetIssues\x12".scanoss.api.common.v2.PurlRequest\x1a\'.scanoss.api.semgrep.v2.SemgrepResponse"!\x82\xd3\xe4\x93\x02\x1b"\x16/api/v2/semgrep/issues:\x01*B\x85\x02Z/github.com/scanoss/papi/api/semgrepv2;semgrepv2\x92\x41\xd0\x01\x12j\n\x17SCANOSS Semgrep Service"J\n\x0fscanoss-semgrep\x12"https://github.com/scanoss/semgrep\x1a\x13support@scanoss.com2\x03\x32.0*\x01\x01\x32\x10\x61pplication/json:\x10\x61pplication/jsonR;\n\x03\x34\x30\x34\x12\x34\n*Returned when the resource does not exist.\x12\x06\n\x04\x9a\x02\x01\x07\x62\x06proto3'
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'scanoss.api.semgrep.v2.scanoss_semgrep_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    DESCRIPTOR._serialized_options = b'Z/github.com/scanoss/papi/api/semgrepv2;semgrepv2\222A\320\001\022j\n\027SCANOSS Semgrep Service"J\n\017scanoss-semgrep\022"https://github.com/scanoss/semgrep\032\023support@scanoss.com2\0032.0*\001\0012\020application/json:\020application/jsonR;\n\003404\0224\n*Returned when the resource does not exist.\022\006\n\004\232\002\001\007'
    _SEMGREP.methods_by_name['Echo']._options = None
    _SEMGREP.methods_by_name['Echo']._serialized_options = b'\202\323\344\223\002\031"\024/api/v2/semgrep/echo:\001*'
    _SEMGREP.methods_by_name['GetIssues']._options = None
    _SEMGREP.methods_by_name[
        'GetIssues'
    ]._serialized_options = b'\202\323\344\223\002\033"\026/api/v2/semgrep/issues:\001*'
    _SEMGREPRESPONSE._serialized_start = 193
    _SEMGREPRESPONSE._serialized_end = 599
    _SEMGREPRESPONSE_ISSUE._serialized_start = 329
    _SEMGREPRESPONSE_ISSUE._serialized_end = 396
    _SEMGREPRESPONSE_FILE._serialized_start = 398
    _SEMGREPRESPONSE_FILE._serialized_end = 498
    _SEMGREPRESPONSE_PURLS._serialized_start = 500
    _SEMGREPRESPONSE_PURLS._serialized_end = 599
    _SEMGREP._serialized_start = 602
    _SEMGREP._serialized_end = 850
# @@protoc_insertion_point(module_scope)
