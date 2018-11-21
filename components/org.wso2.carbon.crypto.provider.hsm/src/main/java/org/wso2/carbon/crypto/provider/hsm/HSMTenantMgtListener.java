package org.wso2.carbon.crypto.provider.hsm;

import iaik.pkcs.pkcs11.Session;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.CertificateHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Implementation of {@link TenantMgtListener} which stores private key and public certificate of the
 * created tenant in the HSM device.
 */
public class HSMTenantMgtListener implements TenantMgtListener {

    private static final int EXEC_ORDER = 21;
    private static Log log = LogFactory.getLog(HSMTenantMgtListener.class);

    private ServerConfigurationService serverConfigurationService;
    private SessionHandler sessionHandler;
    private SlotResolver slotResolver;

    /**
     * Constructor of {@link HSMTenantMgtListener}.
     *
     * @param serverConfigurationService : carbon.xml configuration as a service.
     * @throws CryptoException
     */
    public HSMTenantMgtListener(ServerConfigurationService serverConfigurationService) throws CryptoException {

        this.serverConfigurationService = serverConfigurationService;
        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        slotResolver = new DefaultSlotResolver(serverConfigurationService);
    }

    /**
     * This method retrieves the generated keystore at the tenant creation, using {@link KeyStoreManager} and
     * stores the public certificate and private key in the HSM device.
     *
     * @param tenantInfoBean : Bean object which stores information related to created tenant.
     * @throws StratosException
     */
    @Override
    public void onTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantInfoBean.getTenantDomain())) {
            String errorMessage = "Super tenant domain can't be a new tenant domain.";
            throw new StratosException(errorMessage);
        }
        PrivateKey privateKey;
        Certificate certificate;
        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantInfoBean.getTenantId());

            String keyStoreName = getTenantKeyStoreName(tenantInfoBean.getTenantDomain());

            privateKey = (PrivateKey) keyStoreManager.getPrivateKey(keyStoreName,
                    tenantInfoBean.getTenantDomain());
            certificate = keyStoreManager.getKeyStore(keyStoreName)
                    .getCertificate(tenantInfoBean.getTenantDomain());
        } catch (Exception e) {
            String errorMessage = String.format("Error occurred while retrieving public certificate and " +
                    "private key of tenant - %s", tenantInfoBean.getTenantDomain());
            throw new StratosException(errorMessage, e);
        }
        try {
            PKCS11CertificateData pkcs11CertificateData = PKCS11JCEObjectMapper.mapCertificateJCEToPKCS11(certificate);
            iaik.pkcs.pkcs11.objects.PrivateKey privateKeyToStore =
                    PKCS11JCEObjectMapper.mapPrivateKeyJCEToPKCS11(privateKey);
            privateKeyToStore.getLabel().setCharArrayValue(tenantInfoBean.getTenantDomain().toCharArray());
            pkcs11CertificateData.getCertificate().getLabel().
                    setCharArrayValue(tenantInfoBean.getTenantDomain().toCharArray());
            pkcs11CertificateData.getPublicKey().getLabel().
                    setCharArrayValue(tenantInfoBean.getTenantDomain().toCharArray());
            Session session = initiateSession(CryptoContext.buildEmptyContext(tenantInfoBean.getTenantId(),
                    tenantInfoBean.getTenantDomain()));
            KeyHandler keyHandler = new KeyHandler(session);
            CertificateHandler certificateHandler = new CertificateHandler(session);
            keyHandler.storeKey(privateKeyToStore);
            keyHandler.storeKey(pkcs11CertificateData.getPublicKey());
            certificateHandler.storeCertificate(pkcs11CertificateData.getCertificate());
            sessionHandler.closeSession(session);
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while storing the public certificate and private " +
                    "key of tenant - %s", tenantInfoBean.getTenantDomain());
            throw new StratosException(errorMessage);
        }
    }

    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfo) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantDelete(int tenantId) {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantRename(int tenantId, String oldDomainName,
                               String newDomainName) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public int getListenerOrder() {

        return EXEC_ORDER;
    }

    @Override
    public void onTenantInitialActivation(int tenantId) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantActivation(int tenantId) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantDeactivation(int tenantId) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onSubscriptionPlanChange(int tenentId, String oldPlan,
                                         String newPlan) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onPreDelete(int tenantId) throws StratosException {
        //Implement this method to delete product specific data
    }

    private String getTenantKeyStoreName(String tenantDomain) {

        return tenantDomain.trim().replace(".", "-") + ".jks";
    }

    protected Session initiateSession(CryptoContext cryptoContext) throws CryptoException {

        SlotInfo slotInfo = slotResolver.resolveSlot(cryptoContext);
        return sessionHandler.initiateSession(slotInfo.getSlotID(), slotInfo.getPin(), true);
    }
}
