# Copyright 2017 Sergey Berezin

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A cron job for renewing SSL certificates."""

import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
from google import protobuf
import sys

from protos import domains_pb2


def parse_args(argv):
  parser = argparse.ArgumentParser(description=sys.modules['__main__'].__doc__)
  parser.add_argument('config', help='Absolute path to configuration file.')
  return parser.parse_args(argv)


def read_cert(cert_file):
  with open(cert_file) as f:
    pem_data = f.read().encode('utf-8')
  return x509.load_pem_x509_certificate(pem_data, default_backend())


def is_cert_valid(cert, dt):
  """Check if `cert` is valid at `dt` (datetime in UTC)."""
  return cert.not_valid_before < dt and dt < cert.not_valid_after


def need_renew(cert, days_to_renew, now):
  min_valid_date = now + datetime.timedelta(days=days_to_renew)
  return not (is_cert_valid(cert, now) and is_cert_valid(cert, min_valid_date))


def read_config(config):
  pass


def run(argv):  # pragma: no cover
  args = parse_args(argv)
  config = read_config(args.config)
  now = datetime.datetime.utcnow()
