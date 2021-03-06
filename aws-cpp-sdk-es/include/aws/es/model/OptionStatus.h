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
#include <aws/es/ElasticsearchService_EXPORTS.h>
#include <aws/es/model/OptionState.h>

namespace Aws
{
namespace Utils
{
namespace Json
{
  class JsonValue;
} // namespace Json
} // namespace Utils
namespace ElasticsearchService
{
namespace Model
{

  /**
   * <p>Provides the current status of the entity.</p>
   */
  class AWS_ELASTICSEARCHSERVICE_API OptionStatus
  {
  public:
    OptionStatus();
    OptionStatus(const Aws::Utils::Json::JsonValue& jsonValue);
    OptionStatus& operator=(const Aws::Utils::Json::JsonValue& jsonValue);
    Aws::Utils::Json::JsonValue Jsonize() const;

    /**
     * <p>Timestamp which tells the creation date for the entity.</p>
     */
    inline double GetCreationDate() const{ return m_creationDate; }

    /**
     * <p>Timestamp which tells the creation date for the entity.</p>
     */
    inline void SetCreationDate(double value) { m_creationDateHasBeenSet = true; m_creationDate = value; }

    /**
     * <p>Timestamp which tells the creation date for the entity.</p>
     */
    inline OptionStatus& WithCreationDate(double value) { SetCreationDate(value); return *this;}

    /**
     * <p>Timestamp which tells the last updated time for the entity.</p>
     */
    inline double GetUpdateDate() const{ return m_updateDate; }

    /**
     * <p>Timestamp which tells the last updated time for the entity.</p>
     */
    inline void SetUpdateDate(double value) { m_updateDateHasBeenSet = true; m_updateDate = value; }

    /**
     * <p>Timestamp which tells the last updated time for the entity.</p>
     */
    inline OptionStatus& WithUpdateDate(double value) { SetUpdateDate(value); return *this;}

    /**
     * <p>Specifies the latest version for the entity.</p>
     */
    inline long GetUpdateVersion() const{ return m_updateVersion; }

    /**
     * <p>Specifies the latest version for the entity.</p>
     */
    inline void SetUpdateVersion(long value) { m_updateVersionHasBeenSet = true; m_updateVersion = value; }

    /**
     * <p>Specifies the latest version for the entity.</p>
     */
    inline OptionStatus& WithUpdateVersion(long value) { SetUpdateVersion(value); return *this;}

    /**
     * <p>Provides the <code>OptionState</code> for the Elasticsearch domain.</p>
     */
    inline const OptionState& GetState() const{ return m_state; }

    /**
     * <p>Provides the <code>OptionState</code> for the Elasticsearch domain.</p>
     */
    inline void SetState(const OptionState& value) { m_stateHasBeenSet = true; m_state = value; }

    /**
     * <p>Provides the <code>OptionState</code> for the Elasticsearch domain.</p>
     */
    inline void SetState(OptionState&& value) { m_stateHasBeenSet = true; m_state = value; }

    /**
     * <p>Provides the <code>OptionState</code> for the Elasticsearch domain.</p>
     */
    inline OptionStatus& WithState(const OptionState& value) { SetState(value); return *this;}

    /**
     * <p>Provides the <code>OptionState</code> for the Elasticsearch domain.</p>
     */
    inline OptionStatus& WithState(OptionState&& value) { SetState(value); return *this;}

    /**
     * <p>Indicates whether the Elasticsearch domain is being deleted.</p>
     */
    inline bool GetPendingDeletion() const{ return m_pendingDeletion; }

    /**
     * <p>Indicates whether the Elasticsearch domain is being deleted.</p>
     */
    inline void SetPendingDeletion(bool value) { m_pendingDeletionHasBeenSet = true; m_pendingDeletion = value; }

    /**
     * <p>Indicates whether the Elasticsearch domain is being deleted.</p>
     */
    inline OptionStatus& WithPendingDeletion(bool value) { SetPendingDeletion(value); return *this;}

  private:
    double m_creationDate;
    bool m_creationDateHasBeenSet;
    double m_updateDate;
    bool m_updateDateHasBeenSet;
    long m_updateVersion;
    bool m_updateVersionHasBeenSet;
    OptionState m_state;
    bool m_stateHasBeenSet;
    bool m_pendingDeletion;
    bool m_pendingDeletionHasBeenSet;
  };

} // namespace Model
} // namespace ElasticsearchService
} // namespace Aws
