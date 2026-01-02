/**
 * SPDX-FileCopyrightText: 2024-2026 Sebastien Jodogne, EPL UCLouvain, Belgium
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Orthanc for Education
 * Copyright (C) 2024-2026 Sebastien Jodogne, EPL UCLouvain, Belgium
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


#include "RSAPublicKey.h"

#include "../HttpToolbox.h"
#include "OpenSSLSerializationContext.h"
#include "RSAPrivateKey.h"
#include "SecurityConstants.h"

#include <SerializationToolbox.h>

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>


void RSAPublicKey::LoadFromPrivate(RSAPrivateKey& privateKey)
{
  std::string pem;
  privateKey.SerializePublic(pem);
  Unserialize(pem);
}


void RSAPublicKey::Serialize(std::string& pem)
{
  if (!IsValid())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  OpenSSLSerializationContext context;

  if (!PEM_write_bio_PUBKEY(context.GetValue(), key_.GetValue()))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Failed to write public key to BIO");
  }

  context.Write(pem);
}


void RSAPublicKey::Unserialize(const std::string& pem)
{
  PointerRAII<BIO> bio(BIO_free, 1 /* success code of BIO_free() */);
  bio.Assign(BIO_new_mem_buf(pem.empty() ? NULL : pem.c_str(), pem.size()));

  key_.Assign(PEM_read_bio_PUBKEY(bio.GetValue(), NULL, NULL, NULL));

  if (EVP_PKEY_base_id(key_.GetValue()) != EVP_PKEY_RSA)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "The PEM does not contain a RSA private key");
  }

  PointerRAII<EVP_PKEY_CTX> context(EVP_PKEY_CTX_free);
  context.Assign(EVP_PKEY_CTX_new(key_.GetValue(), NULL));

  if (EVP_PKEY_private_check(context.GetValue()) != 0)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "The PEM contains a RSA private key, not a public key");
  }
}


bool RSAPublicKey::VerifyRS256(const std::string& signature,
                               const std::string& message)
{
  // $ openssl dgst -sha256 -verify /tmp/key -keyform PEM -signature /tmp/signature /tmp/message

  if (!IsValid())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  PointerRAII<EVP_MD_CTX> context(EVP_MD_CTX_free);
  context.Assign(EVP_MD_CTX_new());

  if (EVP_DigestVerifyInit(context.GetValue(), NULL, EVP_sha256(), NULL, key_.GetValue()) != 1 ||
      EVP_DigestVerifyUpdate(context.GetValue(), message.empty() ? NULL : message.c_str(), message.size()) != 1)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot verify a signature");
  }

  return (EVP_DigestVerifyFinal(context.GetValue(),
                                signature.empty() ? NULL : reinterpret_cast<const unsigned char*>(signature.c_str()),
                                signature.size()) == 1);
}


void RSAPublicKey::Import_JWKS_RS256(const Json::Value& key)
{
  if (Orthanc::SerializationToolbox::ReadString(key, JWKS_FIELD_ALG) != "RS256" ||
      Orthanc::SerializationToolbox::ReadString(key, JWKS_FIELD_KTY) != "RSA" ||
      Orthanc::SerializationToolbox::ReadString(key, JWKS_FIELD_USE) != "sig")
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);
  }

  std::string encodedN = Orthanc::SerializationToolbox::ReadString(key, JWKS_FIELD_N);
  std::string encodedE = Orthanc::SerializationToolbox::ReadString(key, JWKS_FIELD_E);

  std::string n, e;
  HttpToolbox::DecodeBase64Url(n, encodedN);
  HttpToolbox::DecodeBase64Url(e, encodedE);

  PointerRAII<BIGNUM> bignumN(BN_free);
  bignumN.Assign(BN_bin2bn(reinterpret_cast<const unsigned char*>(n.c_str()), n.size(), NULL /* create new object */));

  PointerRAII<BIGNUM> bignumE(BN_free);
  bignumE.Assign(BN_bin2bn(reinterpret_cast<const unsigned char*>(e.c_str()), e.size(), NULL /* create new object */));

  PointerRAII<OSSL_PARAM_BLD> builder(OSSL_PARAM_BLD_free);
  builder.Assign(OSSL_PARAM_BLD_new());

  if (OSSL_PARAM_BLD_push_BN(builder.GetValue(), OSSL_PKEY_PARAM_RSA_N, bignumN.GetValue()) != 1 ||
      OSSL_PARAM_BLD_push_BN(builder.GetValue(), OSSL_PKEY_PARAM_RSA_E, bignumE.GetValue()) != 1)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  PointerRAII<OSSL_PARAM> params(OSSL_PARAM_free);
  params.Assign(OSSL_PARAM_BLD_to_param(builder.GetValue()));

  PointerRAII<EVP_PKEY_CTX> context(EVP_PKEY_CTX_free);
  context.Assign(EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL));

  key_.Clear();

  if (EVP_PKEY_fromdata_init(context.GetValue()) != 1 ||
      EVP_PKEY_fromdata(context.GetValue(), &key_.GetValue(), EVP_PKEY_PUBLIC_KEY, params.GetValue()) != 1)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }
}
