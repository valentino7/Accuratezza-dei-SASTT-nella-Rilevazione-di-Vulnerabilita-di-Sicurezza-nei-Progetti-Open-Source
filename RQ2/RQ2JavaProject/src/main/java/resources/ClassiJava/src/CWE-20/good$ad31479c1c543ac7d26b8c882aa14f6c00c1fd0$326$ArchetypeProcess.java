/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.installer.processes;

import org.apache.syncope.installer.utilities.FileSystemUtils;
import com.izforge.izpack.panels.process.AbstractUIProcessHandler;
import java.io.File;
import java.util.Properties;
import org.apache.syncope.installer.files.ConsolePom;
import org.apache.syncope.installer.files.CorePom;
import org.apache.syncope.installer.files.ParentPom;
import org.apache.syncope.installer.utilities.InstallLog;
import org.apache.syncope.installer.utilities.MavenUtils;

public class ArchetypeProcess extends BaseProcess {

    @Override
    public void run(final AbstractUIProcessHandler handler, final String[] args) {
        final String installPath = args[0];
        final String mavenDir = args[1];
        final String groupId = args[2];
        final String artifactId = args[3];
        final String secretKey = args[4];
        final String anonymousKey = args[5];
        final String confDirectory = args[6];
        final String logsDirectory = args[7];
        final String bundlesDirectory = args[8];
        final String modelerDirectory = args[9];
        final String syncopeVersion = args[10];
        final String syncopeAdminPassword = args[11];
        final boolean isProxyEnabled = Boolean.valueOf(args[12]);
        final String proxyHost = args[13];
        final String proxyPort = args[14];
        final String proxyUser = args[15];
        final String proxyPwd = args[16];
        final boolean mavenProxyAutoconf = Boolean.valueOf(args[17]);
        final boolean swagger = Boolean.valueOf(args[18]);
        final boolean activiti = Boolean.valueOf(args[19]);
        final String jwsKey = args[20];

        setSyncopeInstallDir(installPath, artifactId);

        FileSystemUtils fileSystemUtils = new FileSystemUtils(handler);
        fileSystemUtils.createDirectory(installPath);
        InstallLog.initialize(installPath, handler);
        MavenUtils mavenUtils = new MavenUtils(mavenDir, handler);
        File customMavenProxySettings = null;
        if (isProxyEnabled && mavenProxyAutoconf) {
            try {
                customMavenProxySettings =
                        MavenUtils.createSettingsWithProxy(installPath, proxyHost, proxyPort, proxyUser, proxyPwd);
            } catch (Exception e) {
                StringBuilder message = new StringBuilder("Error during creation of custom Maven settings.xml");
                handler.emitError(message.toString(), e.getMessage());
                InstallLog.getInstance().error(message.append('\n').append(e.getMessage()).toString());
            }
        }

        handler.logOutput("########################## IMPORTANT ##########################", true);
        handler.logOutput("See " + InstallLog.getInstance().getFileAbsolutePath() + " for the maven logs", true);
        handler.logOutput("########################## IMPORTANT ##########################", true);
        mavenUtils.archetypeGenerate(
                syncopeVersion, groupId, artifactId, secretKey, anonymousKey, jwsKey, syncopeAdminPassword,
                installPath, customMavenProxySettings);

        if (syncopeVersion.contains("SNAPSHOT")) {
            final File pomFile = new File(syncopeInstallDir + PROPERTIES.getProperty("pomFile"));
            String contentPomFile = fileSystemUtils.readFile(pomFile);
            fileSystemUtils.writeToFile(
                    pomFile,
                    contentPomFile.replace(ParentPom.REPOSITORY_PLACEHOLDER, ParentPom.REPOSITORY_CONTENT_TO_ADD));
        }

        if (swagger) {
            final File pomFile = new File(
                    syncopeInstallDir
                    + File.separator
                    + "core"
                    + File.separator
                    + PROPERTIES.getProperty("pomFile"));
            String contentPomFile = fileSystemUtils.readFile(pomFile);
            fileSystemUtils.writeToFile(
                    pomFile,
                    contentPomFile.replace(CorePom.SWAGGER_PLACEHOLDER, CorePom.SWAGGER_CONTENT_TO_ADD));
        }

        fileSystemUtils.createDirectory(confDirectory);
        fileSystemUtils.createDirectory(logsDirectory);
        fileSystemUtils.createDirectory(bundlesDirectory);
        fileSystemUtils.createDirectory(modelerDirectory);

        if (activiti) {
            File pomFile = new File(
                    syncopeInstallDir
                    + File.separator
                    + "core"
                    + File.separator
                    + PROPERTIES.getProperty("pomFile"));
            String contentPomFile = fileSystemUtils.readFile(pomFile);
            fileSystemUtils.writeToFile(
                    pomFile,
                    contentPomFile.replace(CorePom.ACTIVITI_PLACEHOLDER, CorePom.ACTIVITI_CONTENT_TO_ADD));

            fileSystemUtils.copyFileFromResources("/workflow.properties",
                    syncopeInstallDir + PROPERTIES.getProperty("workflowPropertiesFile"), handler);

            pomFile = new File(
                    syncopeInstallDir
                    + File.separator
                    + "console"
                    + File.separator
                    + PROPERTIES.getProperty("pomFile"));
            contentPomFile = fileSystemUtils.readFile(pomFile);
            fileSystemUtils.writeToFile(
                    pomFile,
                    contentPomFile.replace(ConsolePom.ACTIVITI_PLACEHOLDER, ConsolePom.ACTIVITI_CONTENT_TO_ADD).
                            replace(ConsolePom.MODELER_PLACEHOLDER, ConsolePom.MODELER_CONTENT_TO_ADD));
        }

        final Properties syncopeProperties = new Properties();
        syncopeProperties.setProperty("conf.directory", confDirectory);
        syncopeProperties.setProperty("log.directory", logsDirectory);
        syncopeProperties.setProperty("bundles.directory", bundlesDirectory);
        syncopeProperties.setProperty("activiti-modeler.directory", modelerDirectory);
        mavenUtils.mvnCleanPackageWithProperties(
                installPath + File.separator + artifactId, syncopeProperties, customMavenProxySettings);
    }
}
