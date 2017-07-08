#!/usr/bin/env python
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

import datetime
import logging
try:  # pragma2: no cover
  from unittest import mock
except ImportError:  # pragma3: no cover
  import mock
import os
import shutil
import sys
import tempfile
import unittest

from google import protobuf

# Need to load the top-level module to enable relative imports in cron.
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from acme_tiny_cron import cron
from acme_tiny_cron.protos import domains_pb2


# A self-signed test certificate for `snakeoil.com` valid from
# 2017-07-06T20:50:43Z till 2017-10-04T20:50:43Z (time in UTC).
TEST_CERT = """\
-----BEGIN CERTIFICATE-----
MIID/TCCAuWgAwIBAgIJAICG+0oex4pmMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxFTATBgNVBAMTDHNuYWtlb2lsLmNvbTAeFw0xNzA3MDYy
MDUwNDNaFw0xNzEwMDQyMDUwNDNaMFwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpT
b21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFTAT
BgNVBAMTDHNuYWtlb2lsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKbZ32Q5kvEAvtI8oeHONv7diHo3lC/ZJI+BxBczvYjzXG+1dm035n7cdvM6
as5/aAF7Qwc6tdBLjrkQxarOY/k9IlUGsPD2fC2x+oivwuOvg0VQNpvxFpXJjXXr
oRvQvPVNzLLvF5SRchDwcrteL1bjrPACMvSWW6RXbqpNE9956llxuOZ3l4HPagtH
LjJocjs3ynb8CJHmEEKoVSIvVqkE5ynNBWcFAy0sb5Q5h3LhPqZhZW70oHBTKqVD
shEc7teuVoJTcyeoOrVqgQFYN20PHrNUD76l4/MbU6zVA/rXQO7n+Gziy1RrWMNn
2F4KFhiqWFkhj/pxrHGW/F9DgpsCAwEAAaOBwTCBvjAdBgNVHQ4EFgQUvcyg/jVf
X+ahzsKW1pqe7AG8QuswgY4GA1UdIwSBhjCBg4AUvcyg/jVfX+ahzsKW1pqe7AG8
QuuhYKReMFwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYD
VQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFTATBgNVBAMTDHNuYWtlb2ls
LmNvbYIJAICG+0oex4pmMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEB
AJ65Bk63fSup458unwGkbHdZLaBVy5sUJskgR35ZUA4vjFiwFq888AxC1a5+lAQm
5O0Ldfjel3yAdeAG5BXznWL0ogNkWGuv80zvHRZjbQIFmM8F0CizRRnDqW1ws/FC
jSad2U6DSBI/NQ4roAeJSwMvTnwxNLvIUgbT+MrjnNNIaS+oqsY3/+v5s7Yp8r3b
pkE01+jwxZvV8ewfB0xFQB7OpKxacZKOlPAN6HB8IEKkIwlNvg6FaYjcLakCNT7T
I7y4B2c2uygve6gi8IrTcj0JiEEv/LCXyADLKjMLBFkjgIvB5cZk6artnlV85gPI
hP5qtmfmmdOvRwNUFnQLWo0=
-----END CERTIFICATE-----
"""

def get_config_text(domains=None):
  config_text = """\
    staging_server: "https://staging/"
    production_server: "https://production/"
    account_private_key_path: "/path/to/account.key"
    log_path: "/path/to/acme.log"
  """
  for domain in domains or []:
    config_text += 'domain: {\n' + domain + '\n}\n'
  return config_text


def get_config_proto(config_text):
  config = domains_pb2.Domains()
  protobuf.text_format.Merge(config_text, config)
  return config


def get_domain_text(cert_path='/path/to/cert.crt', mode='STAGING', days=None):
  domain = domains_pb2.Domain()
  days_to_renew = ''
  if days:
    days_to_renew = 'renew_days_before_expiration: {}'.format(days)
  domain_text = """\
      name: "test.domain"
      mode: {mode}
      csr_path: "test_request.csr"
      private_key_path: "test_private.key"
      cert_path: "{cert_path}"
      acme_challenge_path: "test_acme_dir"
      {days_to_renew}
  """.format(cert_path=cert_path, mode=mode, days_to_renew=days_to_renew)
  return domain_text


def get_domain_proto(cert_path='/path/to/cert.crt', mode='STAGING', days=None):
  text = get_domain_text(cert_path, mode, days)
  domain = domains_pb2.Domain()
  protobuf.text_format.Merge(text, domain)
  return domain


def add_time(dt, days=0, seconds=0):
  """Add `days` to `dt` (datetime)."""
  return dt + datetime.timedelta(days=days, seconds=seconds)


class TestCron(unittest.TestCase):
  def setUp(self):
    super(TestCron, self).setUp()
    self.tempdir = tempfile.mkdtemp()
    self.cert_file = os.path.join(self.tempdir, 'cert.crt')
    with open(self.cert_file, 'w') as f:
      f.write(TEST_CERT)
    self.not_valid_before = datetime.datetime(2017, 7, 6, 20, 50, 43)
    self.not_valid_after = datetime.datetime(2017, 10, 4, 20, 50, 43)

  def tearDown(self):
    shutil.rmtree(self.tempdir, ignore_errors=True)

  def test_parse_args(self):
    args = cron.parse_args(['/foo/bar/baz'])
    self.assertEqual(args.config, '/foo/bar/baz')

  def test_setup_logging(self):
    logger = logging.getLogger('test')
    log_file = os.path.join(self.tempdir, 'test.log')
    cron.setup_logging(log_file, logger=logger)
    logger.info('This is a test')
    with open(log_file) as f:
      loglines = f.readlines()
    self.assertIn('This is a test', loglines[0].strip())

  def test_read_cert(self):
    # Smoke test: reading a valid cert must not crash.
    _ = cron.read_cert(self.cert_file)
    # Reading a non-existent cert.
    self.assertIsNone(cron.read_cert('/does/not/exist'))

  def test_is_cert_valid(self):
    cert = cron.read_cert(self.cert_file)
    # Within the valid range
    self.assertTrue(cron.is_cert_valid(cert, add_time(self.not_valid_before, seconds=1)))
    self.assertTrue(cron.is_cert_valid(cert, add_time(self.not_valid_after, seconds=-1)))
    # Right before the valid range
    self.assertFalse(cron.is_cert_valid(cert, self.not_valid_before))
    # Right after the valid range
    self.assertFalse(cron.is_cert_valid(cert, self.not_valid_after))
    # A missing cert
    self.assertFalse(cron.is_cert_valid(None, self.not_valid_before))


  def test_need_renew(self):
    cert = cron.read_cert(self.cert_file)
    # At the beginning of the valid range
    self.assertFalse(cron.need_renew(
        cert, 30, now=add_time(self.not_valid_before, seconds=1)))
    # Close enough to the end of the valid range
    self.assertTrue(cron.need_renew(
        cert, 30, now=add_time(self.not_valid_after, days=-29)))
    # Before the valid range
    self.assertTrue(cron.need_renew(cert, 30, now=self.not_valid_before))
    # After the valid range
    self.assertTrue(cron.need_renew(cert, 30, now=self.not_valid_after))

  def test_read_config(self):
    config_file = os.path.join(self.tempdir, 'domains.cfg')
    with open(config_file, 'w') as f:
      f.write(get_config_text([get_domain_text(), get_domain_text(mode='PRODUCTION')]))
    config = cron.read_config(config_file)

  @mock.patch('acme_tiny_cron.cron.call_acme_tiny', autospec=True)
  def test_issue_cert_success(self, mock_cat):
    mock_cat.return_value = b'TEST CERT'
    # Test a deep non-existent path.
    cert_file = os.path.join(self.tempdir, 'deep', 'path', 'to', 'new_cert.crt')
    domain = get_domain_proto(cert_path=cert_file, mode='STAGING')

    self.assertFalse(os.path.isfile(cert_file))
    res = cron.issue_cert(domain, 'test_account.key', 'https://test_staging',
                          'https://test_prod', self.not_valid_after)
    self.assertTrue(res)
    mock_cat.assert_called_once_with([
      '--account-key', 'test_account.key',
      '--csr', 'test_request.csr',
      '--acme-dir', 'test_acme_dir',
      '--ca', 'https://test_staging'])
    with open(cert_file) as f:
      self.assertEqual(f.read(), 'TEST CERT')

  @mock.patch('acme_tiny_cron.cron.call_acme_tiny', autospec=True)
  def test_issue_cert_failure(self, mock_cat):
    mock_cat.return_value = None
    cert_file = os.path.join(self.tempdir, 'new_cert.crt')
    domain = get_domain_proto(cert_path=cert_file, mode='PRODUCTION')

    self.assertFalse(os.path.isfile(cert_file))
    res = cron.issue_cert(domain, 'test_account.key', 'https://test_staging',
                          'https://test_prod', self.not_valid_after)
    self.assertFalse(res)
    mock_cat.assert_called_once_with([
      '--account-key', 'test_account.key',
      '--csr', 'test_request.csr',
      '--acme-dir', 'test_acme_dir',
      '--ca', 'https://test_prod'])
    self.assertFalse(os.path.isfile(cert_file))

  @mock.patch('acme_tiny_cron.cron.call_acme_tiny', autospec=True)
  def test_process_cert_up_to_date(self, mock_cat):
    mock_cat.return_value = b'NEW CERT'
    domain = get_domain_proto(cert_path=self.cert_file, mode='PRODUCTION')
    # Too early to renew.
    self.assertFalse(cron.process_cert(
        domain, 'test_account.key', 'test_staging', 'test_prod',
        add_time(self.not_valid_before, days=1)))

    self.assertEqual(mock_cat.call_count, 0)

    # Branch coverage: supply alternative days before expiration.
    domain = get_domain_proto(cert_path=self.cert_file, mode='PRODUCTION', days=10)
    self.assertFalse(cron.process_cert(
        domain, 'test_account.key', 'test_staging', 'test_prod',
        add_time(self.not_valid_before, days=1)))

    self.assertEqual(mock_cat.call_count, 0)

  @mock.patch('acme_tiny_cron.cron.call_acme_tiny', autospec=True)
  def test_process_cert_renew_success(self, mock_cat):
    mock_cat.return_value = b'NEW CERT'
    domain = get_domain_proto(cert_path=self.cert_file, mode='PRODUCTION')

    self.assertTrue(cron.process_cert(
        domain, 'test_account.key', 'test_staging', 'test_prod', self.not_valid_after))
    mock_cat.assert_called_once_with([
      '--account-key', 'test_account.key',
      '--csr', 'test_request.csr',
      '--acme-dir', 'test_acme_dir',
      '--ca', 'test_prod'])
    with open(self.cert_file) as f:
      cert = f.read()
    self.assertEqual(cert, 'NEW CERT')

  @mock.patch('acme_tiny_cron.cron.call_acme_tiny', autospec=True)
  def test_process_cert_renew_failure(self, mock_cat):
    mock_cat.return_value = None
    domain = get_domain_proto(cert_path=self.cert_file, mode='PRODUCTION')

    self.assertFalse(cron.process_cert(
        domain, 'test_account.key', 'test_staging', 'test_prod', self.not_valid_after))
    mock_cat.assert_called_once_with([
      '--account-key', 'test_account.key',
      '--csr', 'test_request.csr',
      '--acme-dir', 'test_acme_dir',
      '--ca', 'test_prod'])
    with open(self.cert_file) as f:
      cert = f.read()
    self.assertEqual(cert, TEST_CERT)

  @mock.patch('acme_tiny_cron.cron.call_acme_tiny', autospec=True)
  def test_process_certs_up_to_date(self, mock_cat):
    config = get_config_proto(get_config_text([
        get_domain_text(cert_path=self.cert_file, mode='PRODUCTION', days=10),
        get_domain_text(cert_path=self.cert_file, mode='STAGING'),
    ]))
    self.assertFalse(cron.process_certs(config, add_time(self.not_valid_before, days=1)))
    self.assertEqual(mock_cat.call_count, 0)

  @mock.patch('acme_tiny_cron.cron.call_acme_tiny', autospec=True)
  def test_process_certs_renew(self, mock_cat):
    config = get_config_proto(get_config_text([
        get_domain_text(cert_path=self.cert_file, mode='PRODUCTION', days=10),
        get_domain_text(cert_path=self.cert_file, mode='STAGING'),
    ]))
    mock_cat.side_effect = [b'TEST CERT', b'SHOULD NOT BE USED']
    # Expect only STAGING cert to be renewed (default 30 days before expiration).
    self.assertTrue(cron.process_certs(
        config, add_time(self.not_valid_after, days=-29)))
    self.assertEqual(mock_cat.call_count, 1)
    with open(self.cert_file) as f:
      new_cert = f.read()
    self.assertEqual(new_cert, 'TEST CERT')


if __name__ == '__main__':
  unittest.main()
