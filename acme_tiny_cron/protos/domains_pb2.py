# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: acme_tiny_cron/protos/domains.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='acme_tiny_cron/protos/domains.proto',
  package='acme_tiny_cron',
  syntax='proto3',
  serialized_pb=_b('\n#acme_tiny_cron/protos/domains.proto\x12\x0e\x61\x63me_tiny_cron\"\x98\x01\n\x07\x44omains\x12&\n\x06\x64omain\x18\x01 \x03(\x0b\x32\x16.acme_tiny_cron.Domain\x12\x16\n\x0estaging_server\x18\x02 \x01(\t\x12\x19\n\x11production_server\x18\x03 \x01(\t\x12\x10\n\x08log_path\x18\x04 \x01(\t\x12 \n\x18\x61\x63\x63ount_private_key_path\x18\x05 \x01(\t\"\xe8\x01\n\x06\x44omain\x12\x0c\n\x04name\x18\x01 \x03(\t\x12\x10\n\x08\x63sr_path\x18\x02 \x01(\t\x12\x18\n\x10private_key_path\x18\x03 \x01(\t\x12\x11\n\tcert_path\x18\x04 \x01(\t\x12$\n\x1crenew_days_before_expiration\x18\x05 \x01(\x03\x12)\n\x04mode\x18\x06 \x01(\x0e\x32\x1b.acme_tiny_cron.Domain.Mode\x12\x1b\n\x13\x61\x63me_challenge_path\x18\x07 \x01(\t\"#\n\x04Mode\x12\x0e\n\nPRODUCTION\x10\x00\x12\x0b\n\x07STAGING\x10\x01\x62\x06proto3')
)



_DOMAIN_MODE = _descriptor.EnumDescriptor(
  name='Mode',
  full_name='acme_tiny_cron.Domain.Mode',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='PRODUCTION', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='STAGING', index=1, number=1,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=408,
  serialized_end=443,
)
_sym_db.RegisterEnumDescriptor(_DOMAIN_MODE)


_DOMAINS = _descriptor.Descriptor(
  name='Domains',
  full_name='acme_tiny_cron.Domains',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='domain', full_name='acme_tiny_cron.Domains.domain', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='staging_server', full_name='acme_tiny_cron.Domains.staging_server', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='production_server', full_name='acme_tiny_cron.Domains.production_server', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='log_path', full_name='acme_tiny_cron.Domains.log_path', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='account_private_key_path', full_name='acme_tiny_cron.Domains.account_private_key_path', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=56,
  serialized_end=208,
)


_DOMAIN = _descriptor.Descriptor(
  name='Domain',
  full_name='acme_tiny_cron.Domain',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='acme_tiny_cron.Domain.name', index=0,
      number=1, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='csr_path', full_name='acme_tiny_cron.Domain.csr_path', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='private_key_path', full_name='acme_tiny_cron.Domain.private_key_path', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cert_path', full_name='acme_tiny_cron.Domain.cert_path', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='renew_days_before_expiration', full_name='acme_tiny_cron.Domain.renew_days_before_expiration', index=4,
      number=5, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='mode', full_name='acme_tiny_cron.Domain.mode', index=5,
      number=6, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='acme_challenge_path', full_name='acme_tiny_cron.Domain.acme_challenge_path', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _DOMAIN_MODE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=211,
  serialized_end=443,
)

_DOMAINS.fields_by_name['domain'].message_type = _DOMAIN
_DOMAIN.fields_by_name['mode'].enum_type = _DOMAIN_MODE
_DOMAIN_MODE.containing_type = _DOMAIN
DESCRIPTOR.message_types_by_name['Domains'] = _DOMAINS
DESCRIPTOR.message_types_by_name['Domain'] = _DOMAIN
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Domains = _reflection.GeneratedProtocolMessageType('Domains', (_message.Message,), dict(
  DESCRIPTOR = _DOMAINS,
  __module__ = 'acme_tiny_cron.protos.domains_pb2'
  # @@protoc_insertion_point(class_scope:acme_tiny_cron.Domains)
  ))
_sym_db.RegisterMessage(Domains)

Domain = _reflection.GeneratedProtocolMessageType('Domain', (_message.Message,), dict(
  DESCRIPTOR = _DOMAIN,
  __module__ = 'acme_tiny_cron.protos.domains_pb2'
  # @@protoc_insertion_point(class_scope:acme_tiny_cron.Domain)
  ))
_sym_db.RegisterMessage(Domain)


# @@protoc_insertion_point(module_scope)
