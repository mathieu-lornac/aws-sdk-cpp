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
#include <aws/elasticache/ElastiCache_EXPORTS.h>
#include <aws/core/utils/memory/stl/AWSStreamFwd.h>
#include <aws/core/utils/memory/stl/AWSVector.h>
#include <aws/core/utils/memory/stl/AWSString.h>

namespace Aws
{
namespace Utils
{
namespace Xml
{
  class XmlNode;
} // namespace Xml
} // namespace Utils
namespace ElastiCache
{
namespace Model
{

  /**
   * <p>A group of settings that will be applied to the cache cluster in the future,
   * or that are currently being applied.</p>
   */
  class AWS_ELASTICACHE_API PendingModifiedValues
  {
  public:
    PendingModifiedValues();
    PendingModifiedValues(const Aws::Utils::Xml::XmlNode& xmlNode);
    PendingModifiedValues& operator=(const Aws::Utils::Xml::XmlNode& xmlNode);

    void OutputToStream(Aws::OStream& ostream, const char* location, unsigned index, const char* locationValue) const;
    void OutputToStream(Aws::OStream& oStream, const char* location) const;

    /**
     * <p>The new number of cache nodes for the cache cluster.</p> <p>For clusters
     * running Redis, this value must be 1. For clusters running Memcached, this value
     * must be between 1 and 20.</p>
     */
    inline long GetNumCacheNodes() const{ return m_numCacheNodes; }

    /**
     * <p>The new number of cache nodes for the cache cluster.</p> <p>For clusters
     * running Redis, this value must be 1. For clusters running Memcached, this value
     * must be between 1 and 20.</p>
     */
    inline void SetNumCacheNodes(long value) { m_numCacheNodesHasBeenSet = true; m_numCacheNodes = value; }

    /**
     * <p>The new number of cache nodes for the cache cluster.</p> <p>For clusters
     * running Redis, this value must be 1. For clusters running Memcached, this value
     * must be between 1 and 20.</p>
     */
    inline PendingModifiedValues& WithNumCacheNodes(long value) { SetNumCacheNodes(value); return *this;}

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline const Aws::Vector<Aws::String>& GetCacheNodeIdsToRemove() const{ return m_cacheNodeIdsToRemove; }

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline void SetCacheNodeIdsToRemove(const Aws::Vector<Aws::String>& value) { m_cacheNodeIdsToRemoveHasBeenSet = true; m_cacheNodeIdsToRemove = value; }

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline void SetCacheNodeIdsToRemove(Aws::Vector<Aws::String>&& value) { m_cacheNodeIdsToRemoveHasBeenSet = true; m_cacheNodeIdsToRemove = value; }

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline PendingModifiedValues& WithCacheNodeIdsToRemove(const Aws::Vector<Aws::String>& value) { SetCacheNodeIdsToRemove(value); return *this;}

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline PendingModifiedValues& WithCacheNodeIdsToRemove(Aws::Vector<Aws::String>&& value) { SetCacheNodeIdsToRemove(value); return *this;}

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline PendingModifiedValues& AddCacheNodeIdsToRemove(const Aws::String& value) { m_cacheNodeIdsToRemoveHasBeenSet = true; m_cacheNodeIdsToRemove.push_back(value); return *this; }

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline PendingModifiedValues& AddCacheNodeIdsToRemove(Aws::String&& value) { m_cacheNodeIdsToRemoveHasBeenSet = true; m_cacheNodeIdsToRemove.push_back(value); return *this; }

    /**
     * <p>A list of cache node IDs that are being removed (or will be removed) from the
     * cache cluster. A node ID is a numeric identifier (0001, 0002, etc.).</p>
     */
    inline PendingModifiedValues& AddCacheNodeIdsToRemove(const char* value) { m_cacheNodeIdsToRemoveHasBeenSet = true; m_cacheNodeIdsToRemove.push_back(value); return *this; }

    /**
     * <p>The new cache engine version that the cache cluster will run.</p>
     */
    inline const Aws::String& GetEngineVersion() const{ return m_engineVersion; }

    /**
     * <p>The new cache engine version that the cache cluster will run.</p>
     */
    inline void SetEngineVersion(const Aws::String& value) { m_engineVersionHasBeenSet = true; m_engineVersion = value; }

    /**
     * <p>The new cache engine version that the cache cluster will run.</p>
     */
    inline void SetEngineVersion(Aws::String&& value) { m_engineVersionHasBeenSet = true; m_engineVersion = value; }

    /**
     * <p>The new cache engine version that the cache cluster will run.</p>
     */
    inline void SetEngineVersion(const char* value) { m_engineVersionHasBeenSet = true; m_engineVersion.assign(value); }

    /**
     * <p>The new cache engine version that the cache cluster will run.</p>
     */
    inline PendingModifiedValues& WithEngineVersion(const Aws::String& value) { SetEngineVersion(value); return *this;}

    /**
     * <p>The new cache engine version that the cache cluster will run.</p>
     */
    inline PendingModifiedValues& WithEngineVersion(Aws::String&& value) { SetEngineVersion(value); return *this;}

    /**
     * <p>The new cache engine version that the cache cluster will run.</p>
     */
    inline PendingModifiedValues& WithEngineVersion(const char* value) { SetEngineVersion(value); return *this;}

  private:
    long m_numCacheNodes;
    bool m_numCacheNodesHasBeenSet;
    Aws::Vector<Aws::String> m_cacheNodeIdsToRemove;
    bool m_cacheNodeIdsToRemoveHasBeenSet;
    Aws::String m_engineVersion;
    bool m_engineVersionHasBeenSet;
  };

} // namespace Model
} // namespace ElastiCache
} // namespace Aws
