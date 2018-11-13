/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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

package org.wso2.carbon.crypto.provider.hsm;

import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

import java.io.File;

public class TestUtil {

    private static ServerConfigurationService serverConfigurationService;

    public static ServerConfigurationService getServerConfigurationService() {

        synchronized (TestUtil.class) {
            if (serverConfigurationService == null) {
                serverConfigurationService = ServerConfiguration.getInstance();
                System.setProperty("carbon.home", new File("src/test/java/resources/home").getAbsolutePath());
                try {
                    ((ServerConfiguration) serverConfigurationService).init(
                            System.getProperty("carbon.home") + "/repository/conf/carbon.xml");
                } catch (ServerConfigurationException e) {
                    e.printStackTrace();
                }
            }
        }
        return serverConfigurationService;
    }

    public static SessionHandler getSessionHandler() {

        SessionHandler sessionHandler = null;
        try {
            sessionHandler = SessionHandler.getDefaultSessionHandler(getServerConfigurationService());
        } catch (CryptoException e) {
            System.out.println("Error occurred while instantiating SessionHandler : " + e.getMessage());
        }
        return sessionHandler;
    }
}
