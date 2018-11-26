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

import org.wso2.carbon.crypto.api.CryptoContext;

/**
 * The service contract for slot resolvers.
 * Implementations of this interface resolves slots related to a given context information.
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
