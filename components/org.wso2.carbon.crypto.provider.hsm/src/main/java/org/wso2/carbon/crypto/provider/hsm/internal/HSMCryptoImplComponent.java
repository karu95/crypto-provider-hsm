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

package org.wso2.carbon.crypto.provider.hsm.internal;

import org.apache.commons.lang.StringUtils;
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
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.ExternalCryptoProvider;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.crypto.provider.hsm.HSMBasedExternalCryptoProvider;
import org.wso2.carbon.crypto.provider.hsm.HSMBasedInternalCryptoProvider;
import org.wso2.carbon.crypto.provider.hsm.HSMBasedKeyResolver;
import org.wso2.carbon.crypto.provider.hsm.HSMTenantMgtListener;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

/**
 * The class which is used to deal with the OSGi runtime for service registration and injection.
 */
@Component(
        name = "org.wso2.carbon.crypto.provider.hsm",
        immediate = true
)
public class HSMCryptoImplComponent {

    private static final Log log = LogFactory.getLog(HSMCryptoImplComponent.class);
    private static final String CRYPTO_SERVICE_ENABLING_PROPERTY_PATH = "CryptoService.Enabled";

    private ServiceRegistration<ExternalCryptoProvider> hsmBasedExternalCryptoProviderServiceRegistration;
    private ServiceRegistration<InternalCryptoProvider> hsmBasedInternalCryptoProviderServiceRegistration;
    private ServiceRegistration<KeyResolver> hsmBasedKeyResolverServiceRegistration;
    private ServiceRegistration<TenantMgtListener> tenantMgtListenerServiceRegistration;
    private ServerConfigurationService serverConfigurationService;

    @Activate
    protected void activate(ComponentContext context) {

        if (!isCryptoServiceEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("CryptoService is not enabled.");
            }
            return;
        }

        try {
            BundleContext bundleContext = context.getBundleContext();
            registerProviderImplementations(bundleContext);
            registerHSMTenantMgtListener(bundleContext);
        } catch (Throwable e) {
            String errorMessage = "An error occurred while activating HSM based crypto provider.";
            if (log.isErrorEnabled()) {
                log.error(errorMessage, e);
            }
        }

        if (log.isInfoEnabled()) {
            log.info("HSM Based crypto provider has been activated successfully.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        tenantMgtListenerServiceRegistration.unregister();
        hsmBasedExternalCryptoProviderServiceRegistration.unregister();
        hsmBasedInternalCryptoProviderServiceRegistration.unregister();
        hsmBasedKeyResolverServiceRegistration.unregister();
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

    protected boolean isCryptoServiceEnabled() {

        String enabled = serverConfigurationService.getFirstProperty(CRYPTO_SERVICE_ENABLING_PROPERTY_PATH);
        if (!StringUtils.isBlank(enabled)) {

            if (StringUtils.equals(enabled, "true")) {

                return true;
            }
            return false;
        }
        return false;
    }

    protected void registerProviderImplementations(BundleContext bundleContext) throws CryptoException {

        ExternalCryptoProvider hsmBasedExternalCryptoProvider = getHSMBasedExternalCryptoProvider();

        InternalCryptoProvider hsmBasedInternalCryptoProvider = getHSMBasedInternalCryptoProvider();

        KeyResolver hsmBasedKeyResolver = getHSMBasedKeyResolver();

        hsmBasedExternalCryptoProviderServiceRegistration = bundleContext.
                registerService(ExternalCryptoProvider.class, hsmBasedExternalCryptoProvider, null);
        String infoMessage = "'%s' has been registered.";
        if (log.isDebugEnabled()) {
            log.debug(String.format(infoMessage, "HSMBasedExternalCryptoProvider"));
        }

        hsmBasedInternalCryptoProviderServiceRegistration = bundleContext.
                registerService(InternalCryptoProvider.class, hsmBasedInternalCryptoProvider, null);

        if (log.isDebugEnabled()) {
            log.debug(String.format(infoMessage, "HSMBasedInternalCryptoProvider"));
        }

        hsmBasedKeyResolverServiceRegistration = bundleContext.
                registerService(KeyResolver.class, hsmBasedKeyResolver, null);

        if (log.isDebugEnabled()) {
            log.debug(String.format(infoMessage, "HSMBasedKeyResolver"));
        }
    }

    protected HSMBasedExternalCryptoProvider getHSMBasedExternalCryptoProvider() throws CryptoException {

        HSMBasedExternalCryptoProvider hsmBasedExternalCryptoProvider =
                new HSMBasedExternalCryptoProvider(this.serverConfigurationService);
        return hsmBasedExternalCryptoProvider;
    }

    protected HSMBasedInternalCryptoProvider getHSMBasedInternalCryptoProvider() throws CryptoException {

        HSMBasedInternalCryptoProvider hsmBasedInternalCryptoProvider =
                new HSMBasedInternalCryptoProvider(this.serverConfigurationService);
        return hsmBasedInternalCryptoProvider;
    }

    protected HSMBasedKeyResolver getHSMBasedKeyResolver() {

        HSMBasedKeyResolver hsmBasedKeyResolver = new HSMBasedKeyResolver(this.serverConfigurationService);
        return hsmBasedKeyResolver;
    }

    protected void registerHSMTenantMgtListener(BundleContext bundleContext) throws CryptoException {

        HSMTenantMgtListener hsmTenantMgtListener = new HSMTenantMgtListener(serverConfigurationService);
        tenantMgtListenerServiceRegistration =
                bundleContext.registerService(TenantMgtListener.class, hsmTenantMgtListener, null);
    }
}
