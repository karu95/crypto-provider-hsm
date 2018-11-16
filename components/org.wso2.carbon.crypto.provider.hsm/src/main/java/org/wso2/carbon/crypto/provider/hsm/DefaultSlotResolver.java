package org.wso2.carbon.crypto.provider.hsm;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoContext;

/**
 * This is the {@link SlotResolver} default implementation.
 */
public class DefaultSlotResolver implements SlotResolver {

    private static final String EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.ExternalProvider.ExternalProviderSlotID";
    private static final String INTERNAL_PROVIDER_SLOT_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.InternalProvider.InternalProviderSlotID";

    private ServerConfigurationService serverConfigurationService;

    /**
     * Constructor of {@link DefaultSlotResolver}.
     *
     * @param serverConfigurationService : carbon.xml configuration reading service.
     */
    public DefaultSlotResolver(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    /**
     * This is a simple {@link SlotResolver} implementation based on there are two different slots configured for
     * InternalCryptoProvider and ExternalCryptoProvider.
     *
     * @param cryptoContext : Context information related to the given cryptographic operation.
     * @return {@link SlotInfo}
     */
    @Override
    public SlotInfo resolveSlot(CryptoContext cryptoContext) {

        if (cryptoContext != null) {
            return new SlotInfo(Integer.parseInt(serverConfigurationService
                    .getFirstProperty(EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH)), null);
        } else {
            return new SlotInfo(Integer.parseInt(serverConfigurationService
                    .getFirstProperty(INTERNAL_PROVIDER_SLOT_PROPERTY_PATH)), null);
        }
    }
}
