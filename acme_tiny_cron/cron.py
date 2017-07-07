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
import logging
import logging.handlers
import subprocess
import sys

import acme_tiny
from google import protobuf

from protos import domains_pb2


DEFAULT_DAYS_TO_RENEW = 30


def parse_args(argv):
  parser = argparse.ArgumentParser(description=sys.modules['__main__'].__doc__)
  parser.add_argument('config', help='Absolute path to configuration file.')
  return parser.parse_args(argv)


class LogFormatter(logging.Formatter):
  """Formats log messages in a standard way."""
  def __init__(self):
    super(LogFormatter, self).__init__(
        '[%(levelname)s: %(asctime)s %(filename)s:%(lineno)s] %(message)s')


def setup_logging(log_path, logger=None):
  logger = logger or logging.root
  handler = logging.handlers.RotatingFileHandler(
      filename=log_path,
      maxBytes=10 * 1024 * 1024,
      backupCount=10,
      delay=True,
  )
  handler.setLevel(logging.DEBUG)
  handler.setFormatter(LogFormatter())
  logger.addHandler(handler)
  logger.setLevel(level=logging.DEBUG)


def read_cert(cert_file):
  try:
    with open(cert_file) as f:
      pem_data = f.read().encode('utf-8')
    return x509.load_pem_x509_certificate(pem_data, default_backend())
  except IOError as e:
    return None


def is_cert_valid(cert, dt):
  """Check if `cert` is valid at `dt` (datetime in UTC)."""
  if cert is None:
    return False
  return cert.not_valid_before < dt and dt < cert.not_valid_after


def need_renew(cert, days_to_renew, now):
  min_valid_date = now + datetime.timedelta(days=days_to_renew)
  return not (is_cert_valid(cert, now) and is_cert_valid(cert, min_valid_date))


def read_config(config_path):
  config = domains_pb2.Domains()
  with open(config_path) as f:
    protobuf.text_format.Merge(f.read(), config)
  return config


# Separate minimal function to mock in tests.
def call_acme_tiny(args):  # pragma: no cover
  p = subprocess.Popen(['acme-tiny'] + args,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  # acme-tiny returns the certificate on stdout, and logs on stderr.
  cert, logs = p.communicate()
  for line in logs.splitlines():
    logging.info('acme-tiny: %s', line)
  if p.returncode != 0:
    return None
  return cert


def issue_cert(domain, account_key, staging_server, prod_server, now):
  """Returns True if acme-tiny call succeeds."""
  if domain.mode == domains_pb2.Domain.PRODUCTION:
    server = prod_server
  else:
    server = staging_server
  args = [
      '--account-key', account_key,
      '--csr', domain.csr_path,
      '--acme-dir', domain.acme_challenge_path,
      '--ca', server,
  ]
  cert = call_acme_tiny(args)
  if cert:
    with open(domain.cert_path, 'w') as f:
      f.write(cert)
    return True
  return False


def process_cert(domain, account_key, staging_server, prod_server, now):
  days_to_renew = domain.renew_days_before_expiration
  if not days_to_renew:
    days_to_renew = DEFAULT_DAYS_TO_RENEW
  if need_renew(read_cert(domain.cert_path), days_to_renew, now):
    return issue_cert(domain, account_key, staging_server, prod_server, now)
  return False


def process_certs(config, now):
  """Renew / issue all certificates as appropriate.

  Args:
    config: (proto) parsed configuration
    now:    (datetime) time now in UTC

  Returns:
    True if any cert was issued, False otherwise.
  """
  updated_count = 0
  for domain in config.domain:
    if process_cert(domain, config.account_private_key_path,
                    config.staging_server, config.production_server, now):
      updated_count += 1
  if updated_count:
    logging.info('Updated %d certificates', updated_count)
  else:
    logging.info('All %s certificates are up-to-date.', len(config.domain))
  return updated_count > 0


def run(argv):  # pragma: no cover
  args = parse_args(argv[1:])
  config = read_config(args.config)
  setup_logging(config.log_path)
  now = datetime.datetime.utcnow()
  if process_certs(config, now):
    return 0
  return 1
