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
#include <aws/codedeploy/model/GenericRevisionInfo.h>
#include <aws/core/utils/json/JsonSerializer.h>

#include <utility>

using namespace Aws::CodeDeploy::Model;
using namespace Aws::Utils::Json;
using namespace Aws::Utils;

GenericRevisionInfo::GenericRevisionInfo() : 
    m_descriptionHasBeenSet(false),
    m_deploymentGroupsHasBeenSet(false),
    m_firstUsedTime(0.0),
    m_firstUsedTimeHasBeenSet(false),
    m_lastUsedTime(0.0),
    m_lastUsedTimeHasBeenSet(false),
    m_registerTime(0.0),
    m_registerTimeHasBeenSet(false)
{
}

GenericRevisionInfo::GenericRevisionInfo(const JsonValue& jsonValue) : 
    m_descriptionHasBeenSet(false),
    m_deploymentGroupsHasBeenSet(false),
    m_firstUsedTime(0.0),
    m_firstUsedTimeHasBeenSet(false),
    m_lastUsedTime(0.0),
    m_lastUsedTimeHasBeenSet(false),
    m_registerTime(0.0),
    m_registerTimeHasBeenSet(false)
{
  *this = jsonValue;
}

GenericRevisionInfo& GenericRevisionInfo::operator =(const JsonValue& jsonValue)
{
  if(jsonValue.ValueExists("description"))
  {
    m_description = jsonValue.GetString("description");

    m_descriptionHasBeenSet = true;
  }

  if(jsonValue.ValueExists("deploymentGroups"))
  {
    Array<JsonValue> deploymentGroupsJsonList = jsonValue.GetArray("deploymentGroups");
    for(unsigned deploymentGroupsIndex = 0; deploymentGroupsIndex < deploymentGroupsJsonList.GetLength(); ++deploymentGroupsIndex)
    {
      m_deploymentGroups.push_back(deploymentGroupsJsonList[deploymentGroupsIndex].AsString());
    }
    m_deploymentGroupsHasBeenSet = true;
  }

  if(jsonValue.ValueExists("firstUsedTime"))
  {
    m_firstUsedTime = jsonValue.GetDouble("firstUsedTime");

    m_firstUsedTimeHasBeenSet = true;
  }

  if(jsonValue.ValueExists("lastUsedTime"))
  {
    m_lastUsedTime = jsonValue.GetDouble("lastUsedTime");

    m_lastUsedTimeHasBeenSet = true;
  }

  if(jsonValue.ValueExists("registerTime"))
  {
    m_registerTime = jsonValue.GetDouble("registerTime");

    m_registerTimeHasBeenSet = true;
  }

  return *this;
}

JsonValue GenericRevisionInfo::Jsonize() const
{
  JsonValue payload;

  if(m_descriptionHasBeenSet)
  {
   payload.WithString("description", m_description);

  }

  if(m_deploymentGroupsHasBeenSet)
  {
   Array<JsonValue> deploymentGroupsJsonList(m_deploymentGroups.size());
   for(unsigned deploymentGroupsIndex = 0; deploymentGroupsIndex < deploymentGroupsJsonList.GetLength(); ++deploymentGroupsIndex)
   {
     deploymentGroupsJsonList[deploymentGroupsIndex].AsString(m_deploymentGroups[deploymentGroupsIndex]);
   }
   payload.WithArray("deploymentGroups", std::move(deploymentGroupsJsonList));

  }

  if(m_firstUsedTimeHasBeenSet)
  {
   payload.WithDouble("firstUsedTime", m_firstUsedTime);

  }

  if(m_lastUsedTimeHasBeenSet)
  {
   payload.WithDouble("lastUsedTime", m_lastUsedTime);

  }

  if(m_registerTimeHasBeenSet)
  {
   payload.WithDouble("registerTime", m_registerTime);

  }

  return payload;
}