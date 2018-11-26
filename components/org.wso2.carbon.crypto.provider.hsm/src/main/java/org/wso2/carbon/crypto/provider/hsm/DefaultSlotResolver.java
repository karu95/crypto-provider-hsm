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
