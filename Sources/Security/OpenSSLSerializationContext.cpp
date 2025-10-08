/**
 * SPDX-FileCopyrightText: 2024-2025 Sebastien Jodogne, ICTEAM UCLouvain, Belgium
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Orthanc for Education
 * Copyright (C) 2024-2025 Sebastien Jodogne, EPL UCLouvain, Belgium
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **/


#include "OpenSSLSerializationContext.h"

#include <openssl/buffer.h>


OpenSSLSerializationContext::OpenSSLSerializationContext() :
  bio_(BIO_free, 1 /* success code of BIO_free() */)
{
  bio_.Assign(BIO_new(BIO_s_mem()));
}


void OpenSSLSerializationContext::Write(std::string& pem)
{
  PointerRAII<BUF_MEM> buf(BUF_MEM_free);
  BIO_get_mem_ptr(bio_.GetValue(), &buf.GetValue());

  if (BIO_set_close(bio_.GetValue(), BIO_NOCLOSE) != 1 /* Don't free "bio" when "buf" is freed */ ||
      buf.GetValue() == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Failed to read BUF_MEM");
  }

  pem.assign(buf.GetValue()->data, buf.GetValue()->length);
}
