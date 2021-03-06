/*
* Copyright 2010-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#pragma once
#include <aws/apigateway/APIGateway_EXPORTS.h>
#include <aws/core/utils/stream/ResponseStream.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/Array.h>

namespace Aws
{
template<typename RESULT_TYPE>
class AmazonWebServiceResult;

namespace APIGateway
{
namespace Model
{
  class AWS_APIGATEWAY_API GetExportResult
  {
  public:
    GetExportResult();
    //We have to define these because Microsoft doesn't auto generate them
    GetExportResult(GetExportResult&&);
    GetExportResult& operator=(GetExportResult&&);
    //we delete these because Microsoft doesn't handle move generation correctly
    //and we therefore don't trust them to get it right here either.
    GetExportResult(const GetExportResult&) = delete;
    GetExportResult& operator=(const GetExportResult&) = delete;


    GetExportResult(AmazonWebServiceResult<Utils::Stream::ResponseStream>&& result);
    GetExportResult& operator=(AmazonWebServiceResult<Utils::Stream::ResponseStream>&& result);


    
    inline const Aws::String& GetContentType() const{ return m_contentType; }

    
    inline void SetContentType(const Aws::String& value) { m_contentType = value; }

    
    inline void SetContentType(Aws::String&& value) { m_contentType = value; }

    
    inline void SetContentType(const char* value) { m_contentType.assign(value); }

    
    inline GetExportResult& WithContentType(const Aws::String& value) { SetContentType(value); return *this;}

    
    inline GetExportResult& WithContentType(Aws::String&& value) { SetContentType(value); return *this;}

    
    inline GetExportResult& WithContentType(const char* value) { SetContentType(value); return *this;}

    
    inline const Aws::String& GetContentDisposition() const{ return m_contentDisposition; }

    
    inline void SetContentDisposition(const Aws::String& value) { m_contentDisposition = value; }

    
    inline void SetContentDisposition(Aws::String&& value) { m_contentDisposition = value; }

    
    inline void SetContentDisposition(const char* value) { m_contentDisposition.assign(value); }

    
    inline GetExportResult& WithContentDisposition(const Aws::String& value) { SetContentDisposition(value); return *this;}

    
    inline GetExportResult& WithContentDisposition(Aws::String&& value) { SetContentDisposition(value); return *this;}

    
    inline GetExportResult& WithContentDisposition(const char* value) { SetContentDisposition(value); return *this;}

    
    inline Aws::IOStream& GetBody() { return m_body.GetUnderlyingStream(); }

  private:
    Aws::String m_contentType;
    Aws::String m_contentDisposition;
    Utils::Stream::ResponseStream m_body;
  };

} // namespace Model
} // namespace APIGateway
} // namespace Aws
