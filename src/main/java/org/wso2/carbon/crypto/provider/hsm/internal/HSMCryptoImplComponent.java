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
    private ServerConfigurationService serverConfigurationService;

    @Activate
    public void activate(ComponentContext context) {

        if (!isCryptoServiceEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("CryptoService is not enabled.");
            }
            return;
        }

        try {
            BundleContext bundleContext = context.getBundleContext();
            registerProviderImplementations(bundleContext);
        } catch (Throwable e) {
            String errorMessage = "An error occurred while activating 'org.wso2.carbon.crypto.provider.hsm'.";
            if (log.isErrorEnabled()) {
                log.error(errorMessage, e);
            }
        }

        if (log.isInfoEnabled()) {
            log.info("HSM Based crypto provider has been activated successfully.");
        }
    }

    @Deactivate
    public void deactivate(ComponentContext context) {

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
    public void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    public void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

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
        if (log.isInfoEnabled()) {
            log.info(String.format(infoMessage, "HSMBasedExternalCryptoProvider"));
        }

        hsmBasedInternalCryptoProviderServiceRegistration = bundleContext.
                registerService(InternalCryptoProvider.class, hsmBasedInternalCryptoProvider, null);

        if (log.isInfoEnabled()) {
            log.info(String.format(infoMessage, "HSMBasedInternalCryptoProvider"));
        }

        hsmBasedKeyResolverServiceRegistration = bundleContext.registerService(KeyResolver.class, hsmBasedKeyResolver, null);

        if (log.isInfoEnabled()) {
            log.info(String.format(infoMessage, "HSMBasedKeyResolver"));
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
}
