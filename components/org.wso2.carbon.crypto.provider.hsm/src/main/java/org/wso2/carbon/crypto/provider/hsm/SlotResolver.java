package org.wso2.carbon.crypto.provider.hsm;

import org.wso2.carbon.crypto.api.CryptoContext;

/**
 * The service contract for slot resolvers.
 * Implementations of this provides interface resolves slots related to given context information.
 */
public interface SlotResolver {

    /**
     * Resolves the slot information related to given {@link CryptoContext}.
     *
     * @param cryptoContext : Context information related to the given cryptographic operation.
     * @return {@link SlotInfo}
     */
    SlotInfo resolveSlot(CryptoContext cryptoContext);
}
