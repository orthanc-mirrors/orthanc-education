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


#include "RSAPrivateKey.h"

#include "../HttpToolbox.h"
#include "OpenSSLSerializationContext.h"
#include "SecurityConstants.h"

#include <Toolbox.h>

#include <cassert>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


static void GetBignumFromKey(std::string& data,
                             const EVP_PKEY* key,
                             const std::string& parameterName)
{
  PointerRAII<BIGNUM> bignum(BN_free);
  if (!EVP_PKEY_get_bn_param(key, parameterName.c_str(), &bignum.GetValue()) ||
      bignum.GetValue() == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  int size = BN_num_bytes(bignum.GetValue());
  if (size <= 0)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  data.resize(size);
  assert(!data.empty());
  if (!BN_bn2bin(bignum.GetValue(), reinterpret_cast<unsigned char*>(&data[0])))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }
}


void RSAPrivateKey::Generate(unsigned int bits)
{
  key_.Clear();

  PointerRAII<EVP_PKEY_CTX> context(EVP_PKEY_CTX_free);
  context.Assign(EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL));

  if (EVP_PKEY_keygen_init(context.GetValue()) != 1 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(context.GetValue(), bits) != 1 ||
      EVP_PKEY_generate(context.GetValue(), &key_.GetValue()) != 1)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }
}


void RSAPrivateKey::SerializePrivate(std::string& pem)
{
  if (!IsValid())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  OpenSSLSerializationContext context;

  if (!PEM_write_bio_PrivateKey(context.GetValue(), key_.GetValue(), NULL, NULL, 0, NULL, NULL))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Failed to write private key to BIO");
  }

  context.Write(pem);
}


void RSAPrivateKey::SerializePublic(std::string& pem)
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


void RSAPrivateKey::Unserialize(const std::string& pem)
{
  PointerRAII<BIO> bio(BIO_free, 1 /* success code of BIO_free() */);
  bio.Assign(BIO_new_mem_buf(pem.empty() ? NULL : pem.c_str(), pem.size()));

  key_.Assign(PEM_read_bio_PrivateKey(bio.GetValue(), NULL, NULL, NULL));

  if (EVP_PKEY_base_id(key_.GetValue()) != EVP_PKEY_RSA)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "The PEM does not contain a RSA private key");
  }

  PointerRAII<EVP_PKEY_CTX> context(EVP_PKEY_CTX_free);
  context.Assign(EVP_PKEY_CTX_new(key_.GetValue(), NULL));

  if (EVP_PKEY_private_check(context.GetValue()) != 1)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "The PEM contains a RSA public key, not a private key");
  }
}


void RSAPrivateKey::SignRS256(std::string& signature,
                              const std::string& buffer)
{
  if (!IsValid())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  PointerRAII<EVP_MD_CTX> context(EVP_MD_CTX_free);
  context.Assign(EVP_MD_CTX_new());

  size_t size;

  if (EVP_DigestSignInit(context.GetValue(), NULL, EVP_sha256(), NULL, key_.GetValue()) != 1 ||
      EVP_DigestSignUpdate(context.GetValue(), buffer.empty() ? NULL : buffer.c_str(), buffer.size()) != 1 ||
      EVP_DigestSignFinal(context.GetValue(), NULL, &size) != 1)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot sign a memory buffer");
  }

  signature.resize(size);

  if (size != 0 &&
      EVP_DigestSignFinal(context.GetValue(), reinterpret_cast<unsigned char*>(&signature[0]), &size) != 1)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot sign a memory buffer");
  }
}


void RSAPrivateKey::GetExponent(std::string& exponent)
{
  if (!IsValid())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  GetBignumFromKey(exponent, key_.GetValue(), OSSL_PKEY_PARAM_RSA_E);
}


void RSAPrivateKey::GetModulus(std::string& modulus)
{
  if (!IsValid())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  GetBignumFromKey(modulus, key_.GetValue(), OSSL_PKEY_PARAM_RSA_N);
}


void RSAPrivateKey::Export_JWKS_RS256(Json::Value& target,
                                      const std::string& keyId)
{
  // https://stytch.com/blog/understanding-jwks/

  target = Json::objectValue;
  target[JWKS_FIELD_KTY] = "RSA";
  target[JWKS_FIELD_ALG] = "RS256";
  target[JWKS_FIELD_USE] = "sig";
  target[JWKS_FIELD_KID] = keyId;

  std::string exponent, modulus;
  GetExponent(exponent);
  GetModulus(modulus);

  std::string b64;
  HttpToolbox::EncodeBase64Url(b64, exponent);
  target[JWKS_FIELD_E] = b64;

  HttpToolbox::EncodeBase64Url(b64, modulus);
  target[JWKS_FIELD_N] = b64;
}


void RSAPrivateKey::ForgeJWT(std::string& jwt,
                             const std::string& keyId,
                             const Json::Value& payload)
{
  Json::Value header;
  header[JWKS_FIELD_TYP] = "JWT";
  header[JWKS_FIELD_ALG] = "RS256";
  header[JWKS_FIELD_KID] = keyId;

  std::string headerString, payloadString;
  Orthanc::Toolbox::WriteFastJson(headerString, header);
  Orthanc::Toolbox::WriteFastJson(payloadString, payload);

  std::string headerBase64, payloadBase64;
  HttpToolbox::EncodeBase64Url(headerBase64, headerString);
  HttpToolbox::EncodeBase64Url(payloadBase64, payloadString);

  std::string signature;
  SignRS256(signature, headerBase64 + "." + payloadBase64);

  std::string signatureBase64;
  HttpToolbox::EncodeBase64Url(signatureBase64, signature);

  jwt = headerBase64 + "." + payloadBase64 + "." + signatureBase64;
}
