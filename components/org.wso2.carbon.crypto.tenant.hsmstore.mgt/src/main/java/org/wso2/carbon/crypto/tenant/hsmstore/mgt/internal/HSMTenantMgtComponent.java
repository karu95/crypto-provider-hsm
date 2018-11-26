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

package org.wso2.carbon.crypto.tenant.hsmstore.mgt.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.tenant.hsmstore.mgt.HSMTenantMgtListener;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

/**
 * The class which is used to deal with the OSGi runtime for service registration and injection.
 */
@Component(
        name = "org.wso2.carbon.crypto.tenant.hsmstore.mgt",
        immediate = true
)
public class HSMTenantMgtComponent {

    private static final Log log = LogFactory.getLog(HSMTenantMgtComponent.class);

    private ServerConfigurationService serverConfigurationService;
    private ServiceRegistration<TenantMgtListener> hsmTenantMgtListenerServiceRegistration;

    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            BundleContext bundleContext = componentContext.getBundleContext();
            HSMTenantMgtListener hsmTenantMgtListener = new HSMTenantMgtListener(serverConfigurationService);
            hsmTenantMgtListenerServiceRegistration = bundleContext.registerService(TenantMgtListener.class,
                    hsmTenantMgtListener, null);
        } catch (Throwable e) {
            String errorMessage = "An error occurred while activating HSM tenant management listener.";
            if (log.isErrorEnabled()) {
                log.error(errorMessage, e);
            }
        }
        if (log.isInfoEnabled()) {
            log.info("HSM tenant management listener has been activated successfully.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        hsmTenantMgtListenerServiceRegistration.unregister();
    }

    @Reference(
            name = "serverConfigurationService",
            service = ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            unbind = "unsetServerConfigurationService"
    )
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = null;
    }
}
