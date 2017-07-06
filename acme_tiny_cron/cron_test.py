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
import os
import shutil
import tempfile
import unittest

import cron


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

  def test_is_cert_valid(self):
    cert = cron.read_cert(self.cert_file)
    # Within the valid range
    self.assertTrue(cron.is_cert_valid(cert, add_time(self.not_valid_before, seconds=1)))
    self.assertTrue(cron.is_cert_valid(cert, add_time(self.not_valid_after, seconds=-1)))
    # Right before the valid range
    self.assertFalse(cron.is_cert_valid(cert, self.not_valid_before))
    # Right after the valid range
    self.assertFalse(cron.is_cert_valid(cert, self.not_valid_after))


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


if __name__ == '__main__':
  unittest.main()
