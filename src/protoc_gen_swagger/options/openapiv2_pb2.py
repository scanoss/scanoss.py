# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protoc-gen-swagger/options/openapiv2.proto
"""Generated protocol buffer code."""

from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import any_pb2 as google_dot_protobuf_dot_any__pb2
from google.protobuf import struct_pb2 as google_dot_protobuf_dot_struct__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n*protoc-gen-swagger/options/openapiv2.proto\x12\'grpc.gateway.protoc_gen_swagger.options\x1a\x19google/protobuf/any.proto\x1a\x1cgoogle/protobuf/struct.proto"\xa0\x07\n\x07Swagger\x12\x0f\n\x07swagger\x18\x01 \x01(\t\x12;\n\x04info\x18\x02 \x01(\x0b\x32-.grpc.gateway.protoc_gen_swagger.options.Info\x12\x0c\n\x04host\x18\x03 \x01(\t\x12\x11\n\tbase_path\x18\x04 \x01(\t\x12O\n\x07schemes\x18\x05 \x03(\x0e\x32>.grpc.gateway.protoc_gen_swagger.options.Swagger.SwaggerScheme\x12\x10\n\x08\x63onsumes\x18\x06 \x03(\t\x12\x10\n\x08produces\x18\x07 \x03(\t\x12R\n\tresponses\x18\n \x03(\x0b\x32?.grpc.gateway.protoc_gen_swagger.options.Swagger.ResponsesEntry\x12Z\n\x14security_definitions\x18\x0b \x01(\x0b\x32<.grpc.gateway.protoc_gen_swagger.options.SecurityDefinitions\x12N\n\x08security\x18\x0c \x03(\x0b\x32<.grpc.gateway.protoc_gen_swagger.options.SecurityRequirement\x12U\n\rexternal_docs\x18\x0e \x01(\x0b\x32>.grpc.gateway.protoc_gen_swagger.options.ExternalDocumentation\x12T\n\nextensions\x18\x0f \x03(\x0b\x32@.grpc.gateway.protoc_gen_swagger.options.Swagger.ExtensionsEntry\x1a\x63\n\x0eResponsesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12@\n\x05value\x18\x02 \x01(\x0b\x32\x31.grpc.gateway.protoc_gen_swagger.options.Response:\x02\x38\x01\x1aI\n\x0f\x45xtensionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12%\n\x05value\x18\x02 \x01(\x0b\x32\x16.google.protobuf.Value:\x02\x38\x01"B\n\rSwaggerScheme\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x08\n\x04HTTP\x10\x01\x12\t\n\x05HTTPS\x10\x02\x12\x06\n\x02WS\x10\x03\x12\x07\n\x03WSS\x10\x04J\x04\x08\x08\x10\tJ\x04\x08\t\x10\nJ\x04\x08\r\x10\x0e"\xa9\x05\n\tOperation\x12\x0c\n\x04tags\x18\x01 \x03(\t\x12\x0f\n\x07summary\x18\x02 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t\x12U\n\rexternal_docs\x18\x04 \x01(\x0b\x32>.grpc.gateway.protoc_gen_swagger.options.ExternalDocumentation\x12\x14\n\x0coperation_id\x18\x05 \x01(\t\x12\x10\n\x08\x63onsumes\x18\x06 \x03(\t\x12\x10\n\x08produces\x18\x07 \x03(\t\x12T\n\tresponses\x18\t \x03(\x0b\x32\x41.grpc.gateway.protoc_gen_swagger.options.Operation.ResponsesEntry\x12\x0f\n\x07schemes\x18\n \x03(\t\x12\x12\n\ndeprecated\x18\x0b \x01(\x08\x12N\n\x08security\x18\x0c \x03(\x0b\x32<.grpc.gateway.protoc_gen_swagger.options.SecurityRequirement\x12V\n\nextensions\x18\r \x03(\x0b\x32\x42.grpc.gateway.protoc_gen_swagger.options.Operation.ExtensionsEntry\x1a\x63\n\x0eResponsesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12@\n\x05value\x18\x02 \x01(\x0b\x32\x31.grpc.gateway.protoc_gen_swagger.options.Response:\x02\x38\x01\x1aI\n\x0f\x45xtensionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12%\n\x05value\x18\x02 \x01(\x0b\x32\x16.google.protobuf.Value:\x02\x38\x01J\x04\x08\x08\x10\t"\xab\x01\n\x06Header\x12\x13\n\x0b\x64\x65scription\x18\x01 \x01(\t\x12\x0c\n\x04type\x18\x02 \x01(\t\x12\x0e\n\x06\x66ormat\x18\x03 \x01(\t\x12\x0f\n\x07\x64\x65\x66\x61ult\x18\x06 \x01(\t\x12\x0f\n\x07pattern\x18\r \x01(\tJ\x04\x08\x04\x10\x05J\x04\x08\x05\x10\x06J\x04\x08\x07\x10\x08J\x04\x08\x08\x10\tJ\x04\x08\t\x10\nJ\x04\x08\n\x10\x0bJ\x04\x08\x0b\x10\x0cJ\x04\x08\x0c\x10\rJ\x04\x08\x0e\x10\x0fJ\x04\x08\x0f\x10\x10J\x04\x08\x10\x10\x11J\x04\x08\x11\x10\x12J\x04\x08\x12\x10\x13"\xb8\x04\n\x08Response\x12\x13\n\x0b\x64\x65scription\x18\x01 \x01(\t\x12?\n\x06schema\x18\x02 \x01(\x0b\x32/.grpc.gateway.protoc_gen_swagger.options.Schema\x12O\n\x07headers\x18\x03 \x03(\x0b\x32>.grpc.gateway.protoc_gen_swagger.options.Response.HeadersEntry\x12Q\n\x08\x65xamples\x18\x04 \x03(\x0b\x32?.grpc.gateway.protoc_gen_swagger.options.Response.ExamplesEntry\x12U\n\nextensions\x18\x05 \x03(\x0b\x32\x41.grpc.gateway.protoc_gen_swagger.options.Response.ExtensionsEntry\x1a_\n\x0cHeadersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12>\n\x05value\x18\x02 \x01(\x0b\x32/.grpc.gateway.protoc_gen_swagger.options.Header:\x02\x38\x01\x1a/\n\rExamplesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1aI\n\x0f\x45xtensionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12%\n\x05value\x18\x02 \x01(\x0b\x32\x16.google.protobuf.Value:\x02\x38\x01"\xf9\x02\n\x04Info\x12\r\n\x05title\x18\x01 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x02 \x01(\t\x12\x18\n\x10terms_of_service\x18\x03 \x01(\t\x12\x41\n\x07\x63ontact\x18\x04 \x01(\x0b\x32\x30.grpc.gateway.protoc_gen_swagger.options.Contact\x12\x41\n\x07license\x18\x05 \x01(\x0b\x32\x30.grpc.gateway.protoc_gen_swagger.options.License\x12\x0f\n\x07version\x18\x06 \x01(\t\x12Q\n\nextensions\x18\x07 \x03(\x0b\x32=.grpc.gateway.protoc_gen_swagger.options.Info.ExtensionsEntry\x1aI\n\x0f\x45xtensionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12%\n\x05value\x18\x02 \x01(\x0b\x32\x16.google.protobuf.Value:\x02\x38\x01"3\n\x07\x43ontact\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0b\n\x03url\x18\x02 \x01(\t\x12\r\n\x05\x65mail\x18\x03 \x01(\t"$\n\x07License\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0b\n\x03url\x18\x02 \x01(\t"9\n\x15\x45xternalDocumentation\x12\x13\n\x0b\x64\x65scription\x18\x01 \x01(\t\x12\x0b\n\x03url\x18\x02 \x01(\t"\x9c\x02\n\x06Schema\x12H\n\x0bjson_schema\x18\x01 \x01(\x0b\x32\x33.grpc.gateway.protoc_gen_swagger.options.JSONSchema\x12\x15\n\rdiscriminator\x18\x02 \x01(\t\x12\x11\n\tread_only\x18\x03 \x01(\x08\x12U\n\rexternal_docs\x18\x05 \x01(\x0b\x32>.grpc.gateway.protoc_gen_swagger.options.ExternalDocumentation\x12)\n\x07\x65xample\x18\x06 \x01(\x0b\x32\x14.google.protobuf.AnyB\x02\x18\x01\x12\x16\n\x0e\x65xample_string\x18\x07 \x01(\tJ\x04\x08\x04\x10\x05"\xe3\x05\n\nJSONSchema\x12\x0b\n\x03ref\x18\x03 \x01(\t\x12\r\n\x05title\x18\x05 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x06 \x01(\t\x12\x0f\n\x07\x64\x65\x66\x61ult\x18\x07 \x01(\t\x12\x11\n\tread_only\x18\x08 \x01(\x08\x12\x0f\n\x07\x65xample\x18\t \x01(\t\x12\x13\n\x0bmultiple_of\x18\n \x01(\x01\x12\x0f\n\x07maximum\x18\x0b \x01(\x01\x12\x19\n\x11\x65xclusive_maximum\x18\x0c \x01(\x08\x12\x0f\n\x07minimum\x18\r \x01(\x01\x12\x19\n\x11\x65xclusive_minimum\x18\x0e \x01(\x08\x12\x12\n\nmax_length\x18\x0f \x01(\x04\x12\x12\n\nmin_length\x18\x10 \x01(\x04\x12\x0f\n\x07pattern\x18\x11 \x01(\t\x12\x11\n\tmax_items\x18\x14 \x01(\x04\x12\x11\n\tmin_items\x18\x15 \x01(\x04\x12\x14\n\x0cunique_items\x18\x16 \x01(\x08\x12\x16\n\x0emax_properties\x18\x18 \x01(\x04\x12\x16\n\x0emin_properties\x18\x19 \x01(\x04\x12\x10\n\x08required\x18\x1a \x03(\t\x12\r\n\x05\x61rray\x18" \x03(\t\x12W\n\x04type\x18# \x03(\x0e\x32I.grpc.gateway.protoc_gen_swagger.options.JSONSchema.JSONSchemaSimpleTypes\x12\x0e\n\x06\x66ormat\x18$ \x01(\t\x12\x0c\n\x04\x65num\x18. \x03(\t"w\n\x15JSONSchemaSimpleTypes\x12\x0b\n\x07UNKNOWN\x10\x00\x12\t\n\x05\x41RRAY\x10\x01\x12\x0b\n\x07\x42OOLEAN\x10\x02\x12\x0b\n\x07INTEGER\x10\x03\x12\x08\n\x04NULL\x10\x04\x12\n\n\x06NUMBER\x10\x05\x12\n\n\x06OBJECT\x10\x06\x12\n\n\x06STRING\x10\x07J\x04\x08\x01\x10\x02J\x04\x08\x02\x10\x03J\x04\x08\x04\x10\x05J\x04\x08\x12\x10\x13J\x04\x08\x13\x10\x14J\x04\x08\x17\x10\x18J\x04\x08\x1b\x10\x1cJ\x04\x08\x1c\x10\x1dJ\x04\x08\x1d\x10\x1eJ\x04\x08\x1e\x10"J\x04\x08%\x10*J\x04\x08*\x10+J\x04\x08+\x10."w\n\x03Tag\x12\x13\n\x0b\x64\x65scription\x18\x02 \x01(\t\x12U\n\rexternal_docs\x18\x03 \x01(\x0b\x32>.grpc.gateway.protoc_gen_swagger.options.ExternalDocumentationJ\x04\x08\x01\x10\x02"\xdd\x01\n\x13SecurityDefinitions\x12\\\n\x08security\x18\x01 \x03(\x0b\x32J.grpc.gateway.protoc_gen_swagger.options.SecurityDefinitions.SecurityEntry\x1ah\n\rSecurityEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x46\n\x05value\x18\x02 \x01(\x0b\x32\x37.grpc.gateway.protoc_gen_swagger.options.SecurityScheme:\x02\x38\x01"\x96\x06\n\x0eSecurityScheme\x12J\n\x04type\x18\x01 \x01(\x0e\x32<.grpc.gateway.protoc_gen_swagger.options.SecurityScheme.Type\x12\x13\n\x0b\x64\x65scription\x18\x02 \x01(\t\x12\x0c\n\x04name\x18\x03 \x01(\t\x12\x46\n\x02in\x18\x04 \x01(\x0e\x32:.grpc.gateway.protoc_gen_swagger.options.SecurityScheme.In\x12J\n\x04\x66low\x18\x05 \x01(\x0e\x32<.grpc.gateway.protoc_gen_swagger.options.SecurityScheme.Flow\x12\x19\n\x11\x61uthorization_url\x18\x06 \x01(\t\x12\x11\n\ttoken_url\x18\x07 \x01(\t\x12?\n\x06scopes\x18\x08 \x01(\x0b\x32/.grpc.gateway.protoc_gen_swagger.options.Scopes\x12[\n\nextensions\x18\t \x03(\x0b\x32G.grpc.gateway.protoc_gen_swagger.options.SecurityScheme.ExtensionsEntry\x1aI\n\x0f\x45xtensionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12%\n\x05value\x18\x02 \x01(\x0b\x32\x16.google.protobuf.Value:\x02\x38\x01"K\n\x04Type\x12\x10\n\x0cTYPE_INVALID\x10\x00\x12\x0e\n\nTYPE_BASIC\x10\x01\x12\x10\n\x0cTYPE_API_KEY\x10\x02\x12\x0f\n\x0bTYPE_OAUTH2\x10\x03"1\n\x02In\x12\x0e\n\nIN_INVALID\x10\x00\x12\x0c\n\x08IN_QUERY\x10\x01\x12\r\n\tIN_HEADER\x10\x02"j\n\x04\x46low\x12\x10\n\x0c\x46LOW_INVALID\x10\x00\x12\x11\n\rFLOW_IMPLICIT\x10\x01\x12\x11\n\rFLOW_PASSWORD\x10\x02\x12\x14\n\x10\x46LOW_APPLICATION\x10\x03\x12\x14\n\x10\x46LOW_ACCESS_CODE\x10\x04"\xc9\x02\n\x13SecurityRequirement\x12s\n\x14security_requirement\x18\x01 \x03(\x0b\x32U.grpc.gateway.protoc_gen_swagger.options.SecurityRequirement.SecurityRequirementEntry\x1a)\n\x18SecurityRequirementValue\x12\r\n\x05scope\x18\x01 \x03(\t\x1a\x91\x01\n\x18SecurityRequirementEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x64\n\x05value\x18\x02 \x01(\x0b\x32U.grpc.gateway.protoc_gen_swagger.options.SecurityRequirement.SecurityRequirementValue:\x02\x38\x01"\x81\x01\n\x06Scopes\x12I\n\x05scope\x18\x01 \x03(\x0b\x32:.grpc.gateway.protoc_gen_swagger.options.Scopes.ScopeEntry\x1a,\n\nScopeEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x42\x43ZAgithub.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger/optionsb\x06proto3'
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'protoc_gen_swagger.options.openapiv2_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    DESCRIPTOR._serialized_options = b'ZAgithub.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger/options'
    _SWAGGER_RESPONSESENTRY._options = None
    _SWAGGER_RESPONSESENTRY._serialized_options = b'8\001'
    _SWAGGER_EXTENSIONSENTRY._options = None
    _SWAGGER_EXTENSIONSENTRY._serialized_options = b'8\001'
    _OPERATION_RESPONSESENTRY._options = None
    _OPERATION_RESPONSESENTRY._serialized_options = b'8\001'
    _OPERATION_EXTENSIONSENTRY._options = None
    _OPERATION_EXTENSIONSENTRY._serialized_options = b'8\001'
    _RESPONSE_HEADERSENTRY._options = None
    _RESPONSE_HEADERSENTRY._serialized_options = b'8\001'
    _RESPONSE_EXAMPLESENTRY._options = None
    _RESPONSE_EXAMPLESENTRY._serialized_options = b'8\001'
    _RESPONSE_EXTENSIONSENTRY._options = None
    _RESPONSE_EXTENSIONSENTRY._serialized_options = b'8\001'
    _INFO_EXTENSIONSENTRY._options = None
    _INFO_EXTENSIONSENTRY._serialized_options = b'8\001'
    _SCHEMA.fields_by_name['example']._options = None
    _SCHEMA.fields_by_name['example']._serialized_options = b'\030\001'
    _SECURITYDEFINITIONS_SECURITYENTRY._options = None
    _SECURITYDEFINITIONS_SECURITYENTRY._serialized_options = b'8\001'
    _SECURITYSCHEME_EXTENSIONSENTRY._options = None
    _SECURITYSCHEME_EXTENSIONSENTRY._serialized_options = b'8\001'
    _SECURITYREQUIREMENT_SECURITYREQUIREMENTENTRY._options = None
    _SECURITYREQUIREMENT_SECURITYREQUIREMENTENTRY._serialized_options = b'8\001'
    _SCOPES_SCOPEENTRY._options = None
    _SCOPES_SCOPEENTRY._serialized_options = b'8\001'
    _SWAGGER._serialized_start = 145
    _SWAGGER._serialized_end = 1073
    _SWAGGER_RESPONSESENTRY._serialized_start = 813
    _SWAGGER_RESPONSESENTRY._serialized_end = 912
    _SWAGGER_EXTENSIONSENTRY._serialized_start = 914
    _SWAGGER_EXTENSIONSENTRY._serialized_end = 987
    _SWAGGER_SWAGGERSCHEME._serialized_start = 989
    _SWAGGER_SWAGGERSCHEME._serialized_end = 1055
    _OPERATION._serialized_start = 1076
    _OPERATION._serialized_end = 1757
    _OPERATION_RESPONSESENTRY._serialized_start = 813
    _OPERATION_RESPONSESENTRY._serialized_end = 912
    _OPERATION_EXTENSIONSENTRY._serialized_start = 914
    _OPERATION_EXTENSIONSENTRY._serialized_end = 987
    _HEADER._serialized_start = 1760
    _HEADER._serialized_end = 1931
    _RESPONSE._serialized_start = 1934
    _RESPONSE._serialized_end = 2502
    _RESPONSE_HEADERSENTRY._serialized_start = 2283
    _RESPONSE_HEADERSENTRY._serialized_end = 2378
    _RESPONSE_EXAMPLESENTRY._serialized_start = 2380
    _RESPONSE_EXAMPLESENTRY._serialized_end = 2427
    _RESPONSE_EXTENSIONSENTRY._serialized_start = 914
    _RESPONSE_EXTENSIONSENTRY._serialized_end = 987
    _INFO._serialized_start = 2505
    _INFO._serialized_end = 2882
    _INFO_EXTENSIONSENTRY._serialized_start = 914
    _INFO_EXTENSIONSENTRY._serialized_end = 987
    _CONTACT._serialized_start = 2884
    _CONTACT._serialized_end = 2935
    _LICENSE._serialized_start = 2937
    _LICENSE._serialized_end = 2973
    _EXTERNALDOCUMENTATION._serialized_start = 2975
    _EXTERNALDOCUMENTATION._serialized_end = 3032
    _SCHEMA._serialized_start = 3035
    _SCHEMA._serialized_end = 3319
    _JSONSCHEMA._serialized_start = 3322
    _JSONSCHEMA._serialized_end = 4061
    _JSONSCHEMA_JSONSCHEMASIMPLETYPES._serialized_start = 3864
    _JSONSCHEMA_JSONSCHEMASIMPLETYPES._serialized_end = 3983
    _TAG._serialized_start = 4063
    _TAG._serialized_end = 4182
    _SECURITYDEFINITIONS._serialized_start = 4185
    _SECURITYDEFINITIONS._serialized_end = 4406
    _SECURITYDEFINITIONS_SECURITYENTRY._serialized_start = 4302
    _SECURITYDEFINITIONS_SECURITYENTRY._serialized_end = 4406
    _SECURITYSCHEME._serialized_start = 4409
    _SECURITYSCHEME._serialized_end = 5199
    _SECURITYSCHEME_EXTENSIONSENTRY._serialized_start = 914
    _SECURITYSCHEME_EXTENSIONSENTRY._serialized_end = 987
    _SECURITYSCHEME_TYPE._serialized_start = 4965
    _SECURITYSCHEME_TYPE._serialized_end = 5040
    _SECURITYSCHEME_IN._serialized_start = 5042
    _SECURITYSCHEME_IN._serialized_end = 5091
    _SECURITYSCHEME_FLOW._serialized_start = 5093
    _SECURITYSCHEME_FLOW._serialized_end = 5199
    _SECURITYREQUIREMENT._serialized_start = 5202
    _SECURITYREQUIREMENT._serialized_end = 5531
    _SECURITYREQUIREMENT_SECURITYREQUIREMENTVALUE._serialized_start = 5342
    _SECURITYREQUIREMENT_SECURITYREQUIREMENTVALUE._serialized_end = 5383
    _SECURITYREQUIREMENT_SECURITYREQUIREMENTENTRY._serialized_start = 5386
    _SECURITYREQUIREMENT_SECURITYREQUIREMENTENTRY._serialized_end = 5531
    _SCOPES._serialized_start = 5534
    _SCOPES._serialized_end = 5663
    _SCOPES_SCOPEENTRY._serialized_start = 5619
    _SCOPES_SCOPEENTRY._serialized_end = 5663
# @@protoc_insertion_point(module_scope)
