# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: scanoss/api/cryptography/v2/scanoss-cryptography.proto
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


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n6scanoss/api/cryptography/v2/scanoss-cryptography.proto\x12\x1bscanoss.api.cryptography.v2\x1a*scanoss/api/common/v2/scanoss-common.proto\x1a\x1cgoogle/api/annotations.proto\x1a,protoc-gen-swagger/options/annotations.proto\"0\n\tAlgorithm\x12\x11\n\talgorithm\x18\x01 \x01(\t\x12\x10\n\x08strength\x18\x02 \x01(\t\"\xf3\x01\n\x11\x41lgorithmResponse\x12\x43\n\x05purls\x18\x01 \x03(\x0b\x32\x34.scanoss.api.cryptography.v2.AlgorithmResponse.Purls\x12\x35\n\x06status\x18\x02 \x01(\x0b\x32%.scanoss.api.common.v2.StatusResponse\x1a\x62\n\x05Purls\x12\x0c\n\x04purl\x18\x01 \x01(\t\x12\x0f\n\x07version\x18\x02 \x01(\t\x12:\n\nalgorithms\x18\x03 \x03(\x0b\x32&.scanoss.api.cryptography.v2.Algorithm\"\x82\x02\n\x19\x41lgorithmsInRangeResponse\x12J\n\x05purls\x18\x01 \x03(\x0b\x32;.scanoss.api.cryptography.v2.AlgorithmsInRangeResponse.Purl\x12\x35\n\x06status\x18\x02 \x01(\x0b\x32%.scanoss.api.common.v2.StatusResponse\x1a\x62\n\x04Purl\x12\x0c\n\x04purl\x18\x01 \x01(\t\x12\x10\n\x08versions\x18\x02 \x03(\t\x12:\n\nalgorithms\x18\x03 \x03(\x0b\x32&.scanoss.api.cryptography.v2.Algorithm\"\xe1\x01\n\x17VersionsInRangeResponse\x12H\n\x05purls\x18\x01 \x03(\x0b\x32\x39.scanoss.api.cryptography.v2.VersionsInRangeResponse.Purl\x12\x35\n\x06status\x18\x02 \x01(\x0b\x32%.scanoss.api.common.v2.StatusResponse\x1a\x45\n\x04Purl\x12\x0c\n\x04purl\x18\x01 \x01(\t\x12\x15\n\rversions_with\x18\x02 \x03(\t\x12\x18\n\x10versions_without\x18\x03 \x03(\t\"}\n\x04Hint\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t\x12\x10\n\x08\x63\x61tegory\x18\x04 \x01(\t\x12\x10\n\x03url\x18\x05 \x01(\tH\x00\x88\x01\x01\x12\x11\n\x04purl\x18\x06 \x01(\tH\x01\x88\x01\x01\x42\x06\n\x04_urlB\x07\n\x05_purl\"\xe1\x01\n\rHintsResponse\x12?\n\x05purls\x18\x01 \x03(\x0b\x32\x30.scanoss.api.cryptography.v2.HintsResponse.Purls\x12\x35\n\x06status\x18\x02 \x01(\x0b\x32%.scanoss.api.common.v2.StatusResponse\x1aX\n\x05Purls\x12\x0c\n\x04purl\x18\x01 \x01(\t\x12\x0f\n\x07version\x18\x02 \x01(\t\x12\x30\n\x05hints\x18\x03 \x03(\x0b\x32!.scanoss.api.cryptography.v2.Hint\"\xee\x01\n\x14HintsInRangeResponse\x12\x45\n\x05purls\x18\x01 \x03(\x0b\x32\x36.scanoss.api.cryptography.v2.HintsInRangeResponse.Purl\x12\x35\n\x06status\x18\x02 \x01(\x0b\x32%.scanoss.api.common.v2.StatusResponse\x1aX\n\x04Purl\x12\x0c\n\x04purl\x18\x01 \x01(\t\x12\x10\n\x08versions\x18\x02 \x03(\t\x12\x30\n\x05hints\x18\x03 \x03(\x0b\x32!.scanoss.api.cryptography.v2.Hint2\x88\x07\n\x0c\x43ryptography\x12u\n\x04\x45\x63ho\x12\".scanoss.api.common.v2.EchoRequest\x1a#.scanoss.api.common.v2.EchoResponse\"$\x82\xd3\xe4\x93\x02\x1e\"\x19/api/v2/cryptography/echo:\x01*\x12\x8f\x01\n\rGetAlgorithms\x12\".scanoss.api.common.v2.PurlRequest\x1a..scanoss.api.cryptography.v2.AlgorithmResponse\"*\x82\xd3\xe4\x93\x02$\"\x1f/api/v2/cryptography/algorithms:\x01*\x12\xa5\x01\n\x14GetAlgorithmsInRange\x12\".scanoss.api.common.v2.PurlRequest\x1a\x36.scanoss.api.cryptography.v2.AlgorithmsInRangeResponse\"1\x82\xd3\xe4\x93\x02+\"&/api/v2/cryptography/algorithmsInRange:\x01*\x12\x9f\x01\n\x12GetVersionsInRange\x12\".scanoss.api.common.v2.PurlRequest\x1a\x34.scanoss.api.cryptography.v2.VersionsInRangeResponse\"/\x82\xd3\xe4\x93\x02)\"$/api/v2/cryptography/versionsInRange:\x01*\x12\x96\x01\n\x0fGetHintsInRange\x12\".scanoss.api.common.v2.PurlRequest\x1a\x31.scanoss.api.cryptography.v2.HintsInRangeResponse\",\x82\xd3\xe4\x93\x02&\"!/api/v2/cryptography/hintsInRange:\x01*\x12\x8b\x01\n\x12GetEncryptionHints\x12\".scanoss.api.common.v2.PurlRequest\x1a*.scanoss.api.cryptography.v2.HintsResponse\"%\x82\xd3\xe4\x93\x02\x1f\"\x1a/api/v2/cryptography/hints:\x01*B\x9e\x02Z9github.com/scanoss/papi/api/cryptographyv2;cryptographyv2\x92\x41\xdf\x01\x12y\n\x1cSCANOSS Cryptography Service\"T\n\x14scanoss-cryptography\x12\'https://github.com/scanoss/crpytography\x1a\x13support@scanoss.com2\x03\x32.0*\x01\x01\x32\x10\x61pplication/json:\x10\x61pplication/jsonR;\n\x03\x34\x30\x34\x12\x34\n*Returned when the resource does not exist.\x12\x06\n\x04\x9a\x02\x01\x07\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'scanoss.api.cryptography.v2.scanoss_cryptography_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z9github.com/scanoss/papi/api/cryptographyv2;cryptographyv2\222A\337\001\022y\n\034SCANOSS Cryptography Service\"T\n\024scanoss-cryptography\022\'https://github.com/scanoss/crpytography\032\023support@scanoss.com2\0032.0*\001\0012\020application/json:\020application/jsonR;\n\003404\0224\n*Returned when the resource does not exist.\022\006\n\004\232\002\001\007'
  _CRYPTOGRAPHY.methods_by_name['Echo']._options = None
  _CRYPTOGRAPHY.methods_by_name['Echo']._serialized_options = b'\202\323\344\223\002\036\"\031/api/v2/cryptography/echo:\001*'
  _CRYPTOGRAPHY.methods_by_name['GetAlgorithms']._options = None
  _CRYPTOGRAPHY.methods_by_name['GetAlgorithms']._serialized_options = b'\202\323\344\223\002$\"\037/api/v2/cryptography/algorithms:\001*'
  _CRYPTOGRAPHY.methods_by_name['GetAlgorithmsInRange']._options = None
  _CRYPTOGRAPHY.methods_by_name['GetAlgorithmsInRange']._serialized_options = b'\202\323\344\223\002+\"&/api/v2/cryptography/algorithmsInRange:\001*'
  _CRYPTOGRAPHY.methods_by_name['GetVersionsInRange']._options = None
  _CRYPTOGRAPHY.methods_by_name['GetVersionsInRange']._serialized_options = b'\202\323\344\223\002)\"$/api/v2/cryptography/versionsInRange:\001*'
  _CRYPTOGRAPHY.methods_by_name['GetHintsInRange']._options = None
  _CRYPTOGRAPHY.methods_by_name['GetHintsInRange']._serialized_options = b'\202\323\344\223\002&\"!/api/v2/cryptography/hintsInRange:\001*'
  _CRYPTOGRAPHY.methods_by_name['GetEncryptionHints']._options = None
  _CRYPTOGRAPHY.methods_by_name['GetEncryptionHints']._serialized_options = b'\202\323\344\223\002\037\"\032/api/v2/cryptography/hints:\001*'
  _ALGORITHM._serialized_start=207
  _ALGORITHM._serialized_end=255
  _ALGORITHMRESPONSE._serialized_start=258
  _ALGORITHMRESPONSE._serialized_end=501
  _ALGORITHMRESPONSE_PURLS._serialized_start=403
  _ALGORITHMRESPONSE_PURLS._serialized_end=501
  _ALGORITHMSINRANGERESPONSE._serialized_start=504
  _ALGORITHMSINRANGERESPONSE._serialized_end=762
  _ALGORITHMSINRANGERESPONSE_PURL._serialized_start=664
  _ALGORITHMSINRANGERESPONSE_PURL._serialized_end=762
  _VERSIONSINRANGERESPONSE._serialized_start=765
  _VERSIONSINRANGERESPONSE._serialized_end=990
  _VERSIONSINRANGERESPONSE_PURL._serialized_start=921
  _VERSIONSINRANGERESPONSE_PURL._serialized_end=990
  _HINT._serialized_start=992
  _HINT._serialized_end=1117
  _HINTSRESPONSE._serialized_start=1120
  _HINTSRESPONSE._serialized_end=1345
  _HINTSRESPONSE_PURLS._serialized_start=1257
  _HINTSRESPONSE_PURLS._serialized_end=1345
  _HINTSINRANGERESPONSE._serialized_start=1348
  _HINTSINRANGERESPONSE._serialized_end=1586
  _HINTSINRANGERESPONSE_PURL._serialized_start=1498
  _HINTSINRANGERESPONSE_PURL._serialized_end=1586
  _CRYPTOGRAPHY._serialized_start=1589
  _CRYPTOGRAPHY._serialized_end=2493
# @@protoc_insertion_point(module_scope)
