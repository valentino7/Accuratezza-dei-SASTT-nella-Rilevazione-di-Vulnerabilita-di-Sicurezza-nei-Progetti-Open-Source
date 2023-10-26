/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.apache.geode.management.internal.configuration.functions;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.apache.logging.log4j.Logger;

import org.apache.geode.cache.execute.Function;
import org.apache.geode.cache.execute.FunctionContext;
import org.apache.geode.distributed.internal.ClusterConfigurationService;
import org.apache.geode.distributed.internal.InternalLocator;
import org.apache.geode.internal.InternalEntity;
import org.apache.geode.internal.logging.LogService;
import org.apache.geode.management.internal.configuration.messages.ConfigurationResponse;
import org.apache.geode.management.internal.security.ResourcePermissions;
import org.apache.geode.security.ResourcePermission;

public class GetClusterConfigurationFunction implements Function, InternalEntity {
  private static final Logger logger = LogService.getLogger();

  @Override
  public void execute(FunctionContext context) {
    ClusterConfigurationService clusterConfigurationService =
        InternalLocator.getLocator().getSharedConfiguration();

    Set<String> groups = (Set<String>) context.getArguments();

    logger.info("Received request for configuration  : {}", groups);

    try {
      ConfigurationResponse response =
          clusterConfigurationService.createConfigurationResponse(groups);
      context.getResultSender().lastResult(response);
    } catch (IOException e) {
      logger.error("Unable to retrieve the cluster configuration", e);
      context.getResultSender().lastResult(e);
    }
  }

  /**
   * this function will return all cluster config which will potentially leak security information.
   * Thus we require all permissions to execute this function
   **/
  public Collection<ResourcePermission> getRequiredPermissions(String regionName) {
    return Collections.singleton(ResourcePermissions.ALL);
  }
}
