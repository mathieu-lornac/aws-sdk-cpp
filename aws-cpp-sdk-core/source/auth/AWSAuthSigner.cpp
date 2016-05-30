/*
  * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  *
  * Licensed under the Apache License, Version 2.0 (the "License").
  * You may not use this file except in compliance with the License.
  * A copy of the License is located at
  *
  *  http://aws.amazon.com/apache2.0
  *
  * or in the "license" file accompanying this file. This file is distributed
  * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
  * express or implied. See the License for the specific language governing
  * permissions and limitations under the License.
  */

#include <aws/core/auth/AWSAuthSigner.h>

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/HttpRequest.h>
#include <aws/core/http/HttpResponse.h>
#include <aws/core/utils/DateTime.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/core/utils/logging/LogMacros.h>
#include <aws/core/utils/memory/AWSMemory.h>
#include <aws/core/utils/crypto/Sha256.h>
#include <aws/core/utils/crypto/MD5.h>
#include <aws/core/utils/crypto/Sha256HMAC.h>

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <math.h>
#include <string.h>

// TO REMOVE

#include <vector>

using namespace Aws;
using namespace Aws::Client;
using namespace Aws::Auth;
using namespace Aws::Http;
using namespace Aws::Utils;
using namespace Aws::Utils::Logging;

static const char* AWS_HMAC_SHA256 = "AWS";
static const char* AWS4_REQUEST = "aws4_request";
static const char* NEWLINE = "\n";
static const char* X_AMZ_SIGNED_HEADERS = "X-Amz-SignedHeaders";
static const char* X_AMZ_ALGORITHM = "X-Amz-Algorithm";
static const char* X_AMZ_CREDENTIAL = "X-Amz-Credential";
static const char* UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
static const char* X_AMZ_SIGNATURE = "X-Amz-Signature";
static const char* LONG_DATE_FORMAT_STR = "%a, %d %b %Y %H:%M:%S GMT";

static const char* SIMPLE_DATE_FORMAT_STR = "%Y%m%d";

static const char* v4LogTag = "AWSAuthV4Signer";

Aws::String CanonicalizeRequestSigningString(HttpRequest& request)
{
  std::cout << "##### SHOULD NOT BE EXEX CanonicalizeRequestSigningString" << std::endl;
    request.CanonicalizeRequest();

    Aws::StringStream signingStringStream;
    signingStringStream << HttpMethodMapper::GetNameForHttpMethod(request.GetMethod());

    signingStringStream << NEWLINE << request.GetUri().GetURLEncodedPath() << NEWLINE;

    if (request.GetQueryString().size() > 1 && request.GetQueryString().find("=") != std::string::npos)
    {
        signingStringStream << request.GetQueryString().substr(1) << NEWLINE;
    }
    else if (request.GetQueryString().size() > 1)
    {
        signingStringStream << request.GetQueryString().substr(1) << "=" << NEWLINE;
    }
    else
    {
        signingStringStream << NEWLINE;
    }

    return signingStringStream.str();
}

AWSAuthV4Signer::AWSAuthV4Signer(const std::shared_ptr<Auth::AWSCredentialsProvider>& credentialsProvider,
    const char* serviceName,
    const Aws::String& region) :
    m_credentialsProvider(credentialsProvider),
    m_serviceName(serviceName),
    m_region(region),
    m_hash(Aws::MakeUnique<Aws::Utils::Crypto::Sha256>(v4LogTag)),
    m_hashMD5(Aws::MakeUnique<Aws::Utils::Crypto::MD5>(v4LogTag)),
    m_HMAC(Aws::MakeUnique<Aws::Utils::Crypto::Sha256HMAC>(v4LogTag))
{
}

AWSAuthV4Signer::~AWSAuthV4Signer()
{
    // empty destructor in .cpp file to keep from needing the implementation of (AWSCredentialsProvider, Sha256, Sha256HMAC) in the header file 
}

bool AWSAuthV4Signer::SignRequest(Aws::Http::HttpRequest& request) const
{
    AWSCredentials credentials = m_credentialsProvider->GetAWSCredentials();

    //don't sign anonymous requests
    if (credentials.GetAWSAccessKeyId().empty() || credentials.GetAWSSecretKey().empty())
    {
        return true;
    }

    if (!credentials.GetSessionToken().empty())
    {
        request.SetAwsSessionToken(credentials.GetSessionToken());
    }

    //calculate date header to use in internal signature (this also goes into date header).
    // TODO change format
    Aws::String dateHeaderValue = DateTime::CalculateGmtTimestampAsString(LONG_DATE_FORMAT_STR);
    request.SetHeaderValue("Date", dateHeaderValue);
    //    request.SetHeaderValue("x-amz-date", dateHeaderValue);
    // Md5 of the payload
    Aws::String payloadHash(ComputePayloadHash(request));
    if (payloadHash.empty())
    {
        return false;
    }

    request.SetHeaderValue("Content-type", "plain/text");
    std::cout << "PLHash: " << payloadHash << std::endl;
    // Canonical headers string creation
    Aws::StringStream headersStream;
    headersStream << Aws::Http::HttpMethodMapper::GetNameForHttpMethod(request.GetMethod()) << NEWLINE;
    //    headersStream << payloadHash << NEWLINE; // payload md5
    headersStream << NEWLINE; // payload md5
    if (request.HasHeader(Http::CONTENT_TYPE_HEADER))
      headersStream << request.GetContentType();
    headersStream << NEWLINE; // Content type line
    headersStream << dateHeaderValue <<  NEWLINE;// Date line

    Aws::String canonicalHeadersString = headersStream.str();
    //calculate signed headers parameter
    //remove that last semi-colon


    // Compute CanonicalExtensionHeaders
    Aws::String canonicalExtensionHeaders = CanonicalExtensionHeaders(request);
    // Compute CanonicalResource
    Aws::String canonicalResource = CanonicalResource(request);
    Aws::String messageToSign = canonicalHeadersString + canonicalExtensionHeaders + canonicalResource;
    std::cout << "########### Google Message to sign: " << NEWLINE << messageToSign << "\n###############" << std::endl;


    //now compute sha256 on that request string
    auto hashResult = m_hash->Calculate(messageToSign);
    if (!hashResult.IsSuccess())
    {
        return false;
    }
    Aws::String simpleDate = DateTime::CalculateGmtTimestampAsString(SIMPLE_DATE_FORMAT_STR);
    auto finalSignature = GenerateSignature(credentials, messageToSign, simpleDate);
    Aws::StringStream ss;
    ss << AWS_HMAC_SHA256 << " " << credentials.GetAWSAccessKeyId() << ":" << finalSignature;
    auto awsAuthString = ss.str();

    std::cout << "############### Signing request with: " << awsAuthString << std::endl;
    request.SetAwsAuthorization(awsAuthString);
    return true;
}

Aws::String AWSAuthV4Signer::CanonicalResource(Aws::Http::HttpRequest& request) const { 
  Aws::StringStream cr;
  cr << request.GetUri().GetPath();
  return cr.str();
}


Aws::String AWSAuthV4Signer::CanonicalExtensionHeaders(Aws::Http::HttpRequest& request) const { 
  Aws::StringStream ceh;
  HeaderValueCollection headers = request.GetHeaders();
  std::vector<std::pair<std::string, std::string> > extH;
  for (auto h : headers) {
    if (!h.first.compare(0, 6, "x-amz-")) {
      std::string headerName = h.first;
      std::transform(headerName.begin(), headerName.end(), headerName.begin(), ::tolower);
      extH.push_back(std::make_pair(headerName, h.second));
    }
  }
  // TODO Sort headers according to their name

  // TODO replace duplicate header names by creating one header name with a comma-separated list of values. Be sure there is no whitespace between the values and be sure that the order of the comma-separated list matches the order that the headers appear in your reques 
  
  // TODO Remove any whitespace around the colon that appears after the header name.
  for (auto h : extH) {
    ceh << h.first << ":" << h.second << NEWLINE;
  }
  return ceh.str();
}

bool AWSAuthV4Signer::PresignRequest(Aws::Http::HttpRequest& request, long long expirationTimeInSeconds) const
{
  std::cout <<  "--> presigning request" << std::endl;
    AWSCredentials credentials = m_credentialsProvider->GetAWSCredentials();

    //don't sign anonymous requests
    if (credentials.GetAWSAccessKeyId().empty() || credentials.GetAWSSecretKey().empty())
    {
        return true;
    }

    Aws::StringStream intConversionStream;
    intConversionStream << expirationTimeInSeconds;
    request.AddQueryStringParameter(Http::X_AMZ_EXPIRES_HEADER, intConversionStream.str());   

    if (!credentials.GetSessionToken().empty())
    {
        request.AddQueryStringParameter(Http::AWS_SECURITY_TOKEN, credentials.GetSessionToken());       
    }

    //calculate date header to use in internal signature (this also goes into date header).
    Aws::String dateQueryValue = DateTime::CalculateGmtTimestampAsString(LONG_DATE_FORMAT_STR);
    //    request.AddQueryStringParameter(Http::AWS_DATE_HEADER, dateQueryValue);

    Aws::StringStream ss;
    ss << Http::HOST_HEADER << ":" << request.GetHeaderValue(Http::HOST_HEADER) << NEWLINE;
    Aws::String canonicalHeadersString(ss.str());
    ss.str("");

    AWS_LOGSTREAM_DEBUG(v4LogTag, "Canonical Header String: " << canonicalHeadersString);

    //calculate signed headers parameter
    Aws::String signedHeadersValue(Http::HOST_HEADER);
    request.AddQueryStringParameter(X_AMZ_SIGNED_HEADERS, signedHeadersValue);
    
    AWS_LOGSTREAM_DEBUG(v4LogTag, "Signed Headers value: " << signedHeadersValue);

    Aws::String simpleDate = DateTime::CalculateGmtTimestampAsString(SIMPLE_DATE_FORMAT_STR);
    ss << credentials.GetAWSAccessKeyId() << "/" << simpleDate
        << "/" << m_region << "/" << m_serviceName << "/" << AWS4_REQUEST;

    request.AddQueryStringParameter(X_AMZ_ALGORITHM, AWS_HMAC_SHA256);
    request.AddQueryStringParameter(X_AMZ_CREDENTIAL, ss.str());
    ss.str("");

    //generate generalized canonicalized request string.
    Aws::String canonicalRequestString = CanonicalizeRequestSigningString(request);

    //append v4 stuff to the canonical request string.
    canonicalRequestString.append(canonicalHeadersString);
    canonicalRequestString.append(NEWLINE);
    canonicalRequestString.append(signedHeadersValue);
    canonicalRequestString.append(NEWLINE);
    canonicalRequestString.append(UNSIGNED_PAYLOAD);
    AWS_LOGSTREAM_DEBUG(v4LogTag, "Canonical Request String: " << canonicalRequestString);

    //now compute sha256 on that request string
    auto hashResult = m_hash->Calculate(canonicalRequestString);
    if (!hashResult.IsSuccess())
    {
        AWS_LOGSTREAM_ERROR(v4LogTag, "Failed to hash (sha256) request string \"" << canonicalRequestString << "\"");
        return false;
    }

    auto sha256Digest = hashResult.GetResult();
    auto cannonicalRequestHash = HashingUtils::HexEncode(sha256Digest);   

    auto stringToSign = GenerateStringToSign(dateQueryValue, simpleDate, cannonicalRequestHash);

    auto finalSigningHash = GenerateSignature(credentials, stringToSign, simpleDate);
    if (finalSigningHash.empty())
    {
        return false;
    }

    //add that the signature to the query string    
    request.AddQueryStringParameter(X_AMZ_SIGNATURE, finalSigningHash);

    return true;
}

Aws::String AWSAuthV4Signer::GenerateSignature(const AWSCredentials& credentials, const Aws::String& stringToSign, const Aws::String& simpleDate) const
{
  std::cout << "---> Final String to sign: " << stringToSign << std::endl;

    Aws::StringStream ss;
    Aws::String signingKey(credentials.GetAWSSecretKey());
    ByteBuffer signingKeyBin = HashingUtils::Base64Decode(signingKey);
    std::cout << "---> SigningKey: " << signingKey << std::endl;
    //  std::cout << "---> SigningKey Bin Len: " << signingKeyBin.GetLength() << std::endl;
    // signingKey = "key";
    Aws::String message = stringToSign;
    //message = "The quick brown fox jumps over the lazy dog";
    auto hashResult = m_HMAC->Calculate(ByteBuffer((unsigned char*)message.c_str(), message.length()),
					ByteBuffer((unsigned char*)signingKey.c_str(), signingKey.length())
					//					signingKeyBin
					);
    if (!hashResult.IsSuccess())
    {
        AWS_LOGSTREAM_ERROR(v4LogTag, "Failed to SHA1 hmac \"" << simpleDate << "\"");
        return "";
    }
    auto finalSigningDigest = hashResult.GetResult();
    auto finalSigningHash = HashingUtils::Base64Encode(finalSigningDigest);
    std::cout << "Hash in hex: " << HashingUtils::HexEncode(finalSigningDigest) << std::endl;;
    return finalSigningHash;
}

Aws::String AWSAuthV4Signer::ComputePayloadHash(Aws::Http::HttpRequest& request) const
{
    //compute hash on payload if it exists.
    auto hashResult = request.GetContentBody() ? m_hashMD5->Calculate(*request.GetContentBody())
        : m_hash->Calculate("");
    if (!hashResult.IsSuccess())
    {
        AWS_LOG_ERROR(v4LogTag, "Unable to hash (md5) request body");
        return "";
    }

    auto sha256Digest = hashResult.GetResult();

    Aws::String payloadHash(HashingUtils::HexEncode(sha256Digest));
    std::cout << "Calculated md5 " << payloadHash << " for payload." << std::endl;
    return payloadHash;
}

Aws::String AWSAuthV4Signer::GenerateStringToSign(const Aws::String& dateValue, const Aws::String& simpleDate, const Aws::String& canonicalRequestHash) const
{
    //generate the actual string we will use in signing the final request.
    Aws::StringStream ss;

    ss << AWS_HMAC_SHA256 << NEWLINE << dateValue << NEWLINE << simpleDate << "/" << m_region << "/"
        << m_serviceName << "/" << AWS4_REQUEST << NEWLINE << canonicalRequestHash;

    return ss.str();
}
