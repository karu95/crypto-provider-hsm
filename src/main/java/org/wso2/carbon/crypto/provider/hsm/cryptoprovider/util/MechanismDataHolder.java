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

    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = null;
        this.authData = null;
    }

    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification, AlgorithmParameterSpec algorithmParameterSpec) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = algorithmParameterSpec;
        this.authData = null;
    }

    public MechanismDataHolder(int operatingMode, String jceMechanismSpecification, AlgorithmParameterSpec algorithmParameterSpec,
                               byte[] authData) {

        this.operatingMode = operatingMode;
        this.jceMechanismSpecification = jceMechanismSpecification;
        this.algorithmParameterSpec = algorithmParameterSpec;
        this.authData = authData;
    }

    public MechanismDataHolder (int operatingMode, String jceMechanismSpecification, byte[] authData) {

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
