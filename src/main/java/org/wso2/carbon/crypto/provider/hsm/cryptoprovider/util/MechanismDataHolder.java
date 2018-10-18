package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util;

import java.security.spec.AlgorithmParameterSpec;


/**
 * A given instance holds required data to resolve a mechanism with parameters.
 */
public class MechanismDataHolder {

    private final int operatingMode;
    private final String jceMechanismSpecification;
    private final AlgorithmParameterSpec algorithmParameterSpec;
    private final byte[] authData;

    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        algorithmParameterSpec = null;
        authData = null;
    }

    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification, AlgorithmParameterSpec algorithmParameterSpec) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = algorithmParameterSpec;
        authData = null;
    }

    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification, AlgorithmParameterSpec algorithmParameterSpec,
                               byte[] authData) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = algorithmParameterSpec;
        this.authData = authData;
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
