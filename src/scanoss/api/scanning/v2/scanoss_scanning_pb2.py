# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: scanoss/api/scanning/v2/scanoss-scanning.proto
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


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n.scanoss/api/scanning/v2/scanoss-scanning.proto\x12\x17scanoss.api.scanning.v2\x1a*scanoss/api/common/v2/scanoss-common.proto\x1a\x1cgoogle/api/annotations.proto\x1a,protoc-gen-swagger/options/annotations.proto\"\xff\x01\n\nHFHRequest\x12\x12\n\nbest_match\x18\x01 \x01(\x08\x12\x11\n\tthreshold\x18\x02 \x01(\x05\x12:\n\x04root\x18\x03 \x01(\x0b\x32,.scanoss.api.scanning.v2.HFHRequest.Children\x1a\x8d\x01\n\x08\x43hildren\x12\x0f\n\x07path_id\x18\x01 \x01(\t\x12\x16\n\x0esim_hash_names\x18\x02 \x01(\t\x12\x18\n\x10sim_hash_content\x18\x03 \x01(\t\x12>\n\x08\x63hildren\x18\x04 \x03(\x0b\x32,.scanoss.api.scanning.v2.HFHRequest.Children\"\xa2\x02\n\x0bHFHResponse\x12<\n\x07results\x18\x01 \x03(\x0b\x32+.scanoss.api.scanning.v2.HFHResponse.Result\x12\x35\n\x06status\x18\x02 \x01(\x0b\x32%.scanoss.api.common.v2.StatusResponse\x1a?\n\tComponent\x12\x0c\n\x04purl\x18\x01 \x01(\t\x12\x10\n\x08versions\x18\x02 \x03(\t\x12\x12\n\nconfidence\x18\x03 \x01(\x02\x1a]\n\x06Result\x12\x0f\n\x07path_id\x18\x01 \x01(\t\x12\x42\n\ncomponents\x18\x02 \x03(\x0b\x32..scanoss.api.scanning.v2.HFHResponse.Component2\x81\x02\n\x08Scanning\x12q\n\x04\x45\x63ho\x12\".scanoss.api.common.v2.EchoRequest\x1a#.scanoss.api.common.v2.EchoResponse\" \x82\xd3\xe4\x93\x02\x1a\"\x15/api/v2/scanning/echo:\x01*\x12\x81\x01\n\x0e\x46olderHashScan\x12#.scanoss.api.scanning.v2.HFHRequest\x1a$.scanoss.api.scanning.v2.HFHResponse\"$\x82\xd3\xe4\x93\x02\x1e\"\x19/api/v2/scanning/hfh/scan:\x01*B\x8a\x02Z1github.com/scanoss/papi/api/scanningv2;scanningv2\x92\x41\xd3\x01\x12m\n\x18SCANOSS Scanning Service\"L\n\x10scanoss-scanning\x12#https://github.com/scanoss/scanning\x1a\x13support@scanoss.com2\x03\x32.0*\x01\x01\x32\x10\x61pplication/json:\x10\x61pplication/jsonR;\n\x03\x34\x30\x34\x12\x34\n*Returned when the resource does not exist.\x12\x06\n\x04\x9a\x02\x01\x07\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'scanoss.api.scanning.v2.scanoss_scanning_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z1github.com/scanoss/papi/api/scanningv2;scanningv2\222A\323\001\022m\n\030SCANOSS Scanning Service\"L\n\020scanoss-scanning\022#https://github.com/scanoss/scanning\032\023support@scanoss.com2\0032.0*\001\0012\020application/json:\020application/jsonR;\n\003404\0224\n*Returned when the resource does not exist.\022\006\n\004\232\002\001\007'
  _SCANNING.methods_by_name['Echo']._options = None
  _SCANNING.methods_by_name['Echo']._serialized_options = b'\202\323\344\223\002\032\"\025/api/v2/scanning/echo:\001*'
  _SCANNING.methods_by_name['FolderHashScan']._options = None
  _SCANNING.methods_by_name['FolderHashScan']._serialized_options = b'\202\323\344\223\002\036\"\031/api/v2/scanning/hfh/scan:\001*'
  _HFHREQUEST._serialized_start=196
  _HFHREQUEST._serialized_end=451
  _HFHREQUEST_CHILDREN._serialized_start=310
  _HFHREQUEST_CHILDREN._serialized_end=451
  _HFHRESPONSE._serialized_start=454
  _HFHRESPONSE._serialized_end=744
  _HFHRESPONSE_COMPONENT._serialized_start=586
  _HFHRESPONSE_COMPONENT._serialized_end=649
  _HFHRESPONSE_RESULT._serialized_start=651
  _HFHRESPONSE_RESULT._serialized_end=744
  _SCANNING._serialized_start=747
  _SCANNING._serialized_end=1004
# @@protoc_insertion_point(module_scope)
