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
package org.apache.geode.management.internal.cli.functions;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.geode.cache.Cache;
import org.apache.geode.cache.Region;
import org.apache.geode.cache.execute.Execution;
import org.apache.geode.cache.execute.Function;
import org.apache.geode.cache.execute.FunctionContext;
import org.apache.geode.cache.execute.FunctionService;
import org.apache.geode.cache.execute.ResultCollector;
import org.apache.geode.distributed.DistributedMember;
import org.apache.geode.internal.ClassPathLoader;
import org.apache.geode.internal.InternalEntity;
import org.apache.geode.internal.cache.InternalCache;
import org.apache.geode.internal.security.SecurityService;
import org.apache.geode.management.internal.cli.i18n.CliStrings;

/**
 * @since GemFire 7.0
 */
public class UserFunctionExecution implements Function<Object[]>, InternalEntity {
  public static final String ID = UserFunctionExecution.class.getName();

  private static final long serialVersionUID = 1L;

  @Override
  public void execute(FunctionContext<Object[]> context) {
    Cache cache = context.getCache();
    DistributedMember member = cache.getDistributedSystem().getDistributedMember();

    try {
      String[] functionArgs = null;
      Object[] args = context.getArguments();
      if (args == null) {
        context.getResultSender().lastResult(new CliFunctionResult(member.getId(), false,
            CliStrings.EXECUTE_FUNCTION__MSG__COULD_NOT_RETRIEVE_ARGUMENTS));
        return;
      }

      String functionId = ((String) args[0]);
      String filterString = ((String) args[1]);
      String resultCollectorName = ((String) args[2]);
      String argumentsString = ((String) args[3]);
      String onRegion = ((String) args[4]);
      Properties credentials = (Properties) args[5];

      SecurityService securityService = ((InternalCache) context.getCache()).getSecurityService();

      try {
        securityService.login(credentials);

        if (argumentsString != null && argumentsString.length() > 0) {
          functionArgs = argumentsString.split(",");
        }
        Set<String> filters = new HashSet<>();
        ResultCollector resultCollectorInstance = null;
        if (resultCollectorName != null && resultCollectorName.length() > 0) {
          resultCollectorInstance = (ResultCollector) ClassPathLoader.getLatest()
              .forName(resultCollectorName).newInstance();
        }
        if (filterString != null && filterString.length() > 0) {
          filters.add(filterString);
        }

        Function<?> function = FunctionService.getFunction(functionId);
        if (function == null) {
          context.getResultSender()
              .lastResult(new CliFunctionResult(member.getId(), false,
                  (CliStrings.format(
                      CliStrings.EXECUTE_FUNCTION__MSG__DOES_NOT_HAVE_FUNCTION_0_REGISTERED,
                      functionId))));
          return;
        }

        // security check
        function.getRequiredPermissions(onRegion).forEach(securityService::authorize);

        Execution execution = null;
        if (onRegion != null && onRegion.length() > 0) {
          Region region = cache.getRegion(onRegion);
          if (region == null) {
            context.getResultSender().lastResult(
                new CliFunctionResult(member.getId(), false, onRegion + " does not exist"));
            return;
          }
          execution = FunctionService.onRegion(region);
        } else {
          execution = FunctionService.onMember(member);
        }

        if (execution == null) {
          context.getResultSender()
              .lastResult(new CliFunctionResult(member.getId(), false,
                  CliStrings.format(
                      CliStrings.EXECUTE_FUNCTION__MSG__ERROR_IN_EXECUTING_0_ON_MEMBER_1_ON_REGION_2_DETAILS_3,
                      functionId, member.getId(), onRegion,
                      CliStrings.EXECUTE_FUNCTION__MSG__ERROR_IN_RETRIEVING_EXECUTOR)));
          return;
        }

        if (resultCollectorInstance != null) {
          execution = execution.withCollector(resultCollectorInstance);
        }

        if (functionArgs != null && functionArgs.length > 0) {
          execution = execution.setArguments(functionArgs);
        }
        if (filters.size() > 0) {
          execution = execution.withFilter(filters);
        }

        List<Object> results = (List<Object>) execution.execute(function.getId()).getResult();
        List<String> resultMessage = new ArrayList<>();
        boolean functionSuccess = true;

        if (results != null) {
          for (Object resultObj : results) {
            if (resultObj != null) {
              if (resultObj instanceof Exception) {
                resultMessage.add(((Exception) resultObj).getMessage());
                functionSuccess = false;
              } else {
                resultMessage.add(resultObj.toString());
              }
            }
          }
        }
        context.getResultSender().lastResult(
            new CliFunctionResult(member.getId(), functionSuccess, resultMessage.toString()));

      } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
        context.getResultSender()
            .lastResult(new CliFunctionResult(member.getId(), false,
                CliStrings.format(
                    CliStrings.EXECUTE_FUNCTION__MSG__RESULT_COLLECTOR_0_NOT_FOUND_ERROR_1,
                    resultCollectorName, e.getMessage())));
      } catch (Exception e) {
        context.getResultSender().lastResult(
            new CliFunctionResult(member.getId(), false, "Exception: " + e.getMessage()));
      } finally {
        securityService.logout();
      }

    } catch (Exception ex) {
      context.getResultSender()
          .lastResult(new CliFunctionResult(member.getId(), false, ex.getMessage()));
    }
  }

  @Override
  public String getId() {
    return UserFunctionExecution.ID;
  }

  @Override
  public boolean isHA() {
    return false;
  }

}
