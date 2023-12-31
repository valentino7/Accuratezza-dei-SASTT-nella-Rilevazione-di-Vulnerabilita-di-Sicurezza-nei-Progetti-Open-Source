/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.transport.servlet;

import java.net.URI;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.transport.AbstractDestination;
import org.apache.cxf.wsdl.http.AddressType;

public final class BaseUrlHelper {
    private BaseUrlHelper() {
    }

    /**
     * Returns base URL which includes scheme, host, port, Servlet context and servlet paths
     * @param request current HttpServletRequest
     * @return base URL
     */
    public static String getBaseURL(HttpServletRequest request) {
        String reqPrefix = request.getRequestURL().toString();        
        String pathInfo = request.getPathInfo() == null ? "" : request.getPathInfo();
        //fix for CXF-898
        if (!"/".equals(pathInfo) || reqPrefix.endsWith("/")) {
            StringBuilder sb = new StringBuilder();
            // request.getScheme(), request.getLocalName() and request.getLocalPort()
            // should be marginally cheaper - provided request.getLocalName() does 
            // return the actual name used in request URI as opposed to localhost
            // consistently across the Servlet stacks
            
            URI uri = URI.create(reqPrefix);
            sb.append(uri.getScheme()).append("://").append(uri.getRawAuthority());
            if (request.getContextPath() != null) {
                sb.append(request.getContextPath());
            }
            if (request.getServletPath() != null) {
                sb.append(request.getServletPath());
            }
            
            reqPrefix = sb.toString();
        } else {
            int matrixParamIndex = reqPrefix.indexOf(";");
            if (matrixParamIndex > 0) {
                reqPrefix = reqPrefix.substring(0, matrixParamIndex);
            }
        }
        return reqPrefix;
    }
    

    public static void setAddress(AbstractDestination dest, String absAddress) {
        dest.getEndpointInfo().setAddress(absAddress);
        if (dest.getEndpointInfo().getExtensor(AddressType.class) != null) {
            dest.getEndpointInfo().getExtensor(AddressType.class).setLocation(absAddress);
        }
    }
}
