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

package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util;

import java.security.spec.AlgorithmParameterSpec;

/**
 * A given instance holds required data to resolve a mechanism with parameters.
 */
public class MechanismDataHolder {

    private int operatingMode;
    private String jceMechanismSpecification;
    private AlgorithmParameterSpec algorithmParameterSpec;
    private byte[] authData;

    /**
     * Constructor of a {@link MechanismDataHolder} instance with only operating mode and algorithm specification.
     *
     * @param operatingMode             : Mode of cryptographic operation
     * @param jceMechanismSpecification : Standard JCE name of the mechanism.
     */
    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = null;
        this.authData = null;
    }

    /**
     * Constructor of a {@link MechanismDataHolder} instance with only operating mode, algorithm specification
     * and algorithm parameters.
     *
     * @param operatingMode             : Mode of cryptographic operation
     * @param jceMechanismSpecification : Standard JCE name of the mechanism.
     * @param algorithmParameterSpec    : Algorithm parameter specification.
     */
    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification, AlgorithmParameterSpec algorithmParameterSpec) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = algorithmParameterSpec;
        this.authData = null;
    }

    /**
     * Constructor of a {@link MechanismDataHolder} instance with only operating mode, algorithm specification,
     * algorithm parameters and authentication data.
     *
     * @param operatingMode             : Mode of cryptographic operation
     * @param jceMechanismSpecification : Standard JCE name of the mechanism.
     * @param algorithmParameterSpec    : Algorithm parameter specification.
     * @param authData                  : Authentication data.
     */
    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification, AlgorithmParameterSpec algorithmParameterSpec,
                               byte[] authData) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = algorithmParameterSpec;
        this.authData = authData;
    }

    /**
     * Constructor of a {@link MechanismDataHolder} instance with only operating mode, algorithm specification,
     * and authentication data.
     *
     * @param operatingMode             : Mode of cryptographic operation
     * @param jceMechanismSpecification : Standard JCE name of the mechanism.
     * @param authData                  : Authentication data.
     */
    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification, byte[] authData) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.authData = authData;
        this.algorithmParameterSpec = null;
    }

    public String getJceMechanismSpecification() {

        return jceMechanismSpecification;
    }

    public AlgorithmParameterSpec getAlgorithmParameterSpec() {

        return algorithmParameterSpec;
    }

    public byte[] getAuthData() {

        return authData;
    }

    public int getOperatingMode() {

        return operatingMode;
    }
}
