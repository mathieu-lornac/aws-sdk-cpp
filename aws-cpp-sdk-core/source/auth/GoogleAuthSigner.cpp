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
#include <aws/core/utils/crypto/Sha256HMAC.h>

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <math.h>
#include <string.h>

using namespace Aws;
using namespace Aws::Client;
using namespace Aws::Auth;
using namespace Aws::Http;
using namespace Aws::Utils;
using namespace Aws::Utils::Logging;

static const char* NEWLINE = "\n";
static const char* LONG_DATE_FORMAT_STR = "%a, %d %b %Y %H:%M:%S GMT";
static const char* v4LogTag = "GoogleAuthSigner";


GoogleAuthSigner::GoogleAuthSigner(const std::shared_ptr<Auth::AWSCredentialsProvider>& credentialsProvider,
    const char* serviceName,
    const Aws::String& region) :
    m_credentialsProvider(credentialsProvider),
    m_serviceName(serviceName),
    m_region(region),
    m_HMAC(Aws::MakeUnique<Aws::Utils::Crypto::Sha1HMAC>(v4LogTag))
{
}

GoogleAuthSigner::~GoogleAuthSigner()
{
  // empty destructor in .cpp file to keep from needing the implementation of (AWSCredentialsProvider, Sha256, Sha256HMAC) in the header file
}

bool GoogleAuthSigner::SignRequest(Aws::Http::HttpRequest& request) const
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
    Aws::String dateHeaderValue = DateTime::CalculateGmtTimestampAsString(LONG_DATE_FORMAT_STR);
    request.SetHeaderValue("Date", dateHeaderValue);
    // TODO Should not be here
    request.SetContentType("plain/text");

    Aws::String messageToSign = CanonicalHeaders(request, dateHeaderValue) + 
      CanonicalExtensionHeaders(request) + CanonicalResource(request);
    AWS_LOGSTREAM_DEBUG(v4LogTag, "Google Message To Sign: " << messageToSign);

    auto finalSignature = GenerateSignature(credentials, messageToSign);

    Aws::StringStream ss;
    ss << "AWS " << credentials.GetAWSAccessKeyId() << ":" << finalSignature;
    auto awsAuthString = ss.str();
    AWS_LOGSTREAM_DEBUG(v4LogTag, "Signing request with: " << awsAuthString);
    request.SetAwsAuthorization(awsAuthString);
    return true;
}

bool GoogleAuthSigner::PresignRequest(Aws::Http::HttpRequest&, long long) const
{
  AWS_LOGSTREAM_DEBUG(v4LogTag, "GoogleAuthSigner PresignRequest not implemented");
  return false;
}

Aws::String GoogleAuthSigner::GenerateSignature(const AWSCredentials& credentials, const Aws::String& stringToSign) const
{
    AWS_LOGSTREAM_DEBUG(v4LogTag, "Final String to sign: " << stringToSign);

    Aws::StringStream ss;
    Aws::String signingKey(credentials.GetAWSSecretKey());

    auto hashResult = m_HMAC->Calculate(ByteBuffer((unsigned char*)stringToSign.c_str(), stringToSign.length()),
        ByteBuffer((unsigned char*)signingKey.c_str(), signingKey.length()));
    if (!hashResult.IsSuccess())
    {
        AWS_LOGSTREAM_ERROR(v4LogTag, "Failed to hmac (sha1) string \"" << stringToSign << "\"");
        return "";
    }
    auto finalSigningDigest = hashResult.GetResult();
    auto finalSigningHash = HashingUtils::Base64Encode(finalSigningDigest);
    AWS_LOGSTREAM_DEBUG(v4LogTag, "Final computed Google signing hash: " << finalSigningHash);
    return finalSigningHash;
}

Aws::String GoogleAuthSigner::CanonicalHeaders(Aws::Http::HttpRequest& request,
                                               const Aws::String &dateHeaderValue) const {
  // Canonical headers string creation
  Aws::StringStream headersStream;
  headersStream << Aws::Http::HttpMethodMapper::GetNameForHttpMethod(request.GetMethod()) << NEWLINE;
  headersStream << NEWLINE; // TODO payload md5 not implemented
  if (request.HasHeader(Http::CONTENT_TYPE_HEADER))
    headersStream << request.GetContentType();
  headersStream << NEWLINE; // Content type line
  headersStream << dateHeaderValue <<  NEWLINE;// Date line
  return headersStream.str();
}

Aws::String GoogleAuthSigner::CanonicalExtensionHeaders(Aws::Http::HttpRequest& request) const {
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

Aws::String GoogleAuthSigner::CanonicalResource(Aws::Http::HttpRequest& request) const {
  Aws::StringStream cr;
  cr << request.GetUri().GetPath();
  return cr.str();
}
