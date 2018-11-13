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

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

import java.io.IOException;
import java.util.HashMap;

/**
 * This class is responsible for handling sessions between application and the HSM.
 */
public class SessionHandler {

    private static final String PKCS11_MODULE_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.HSMConfiguration.PKCS11Module";
    private static Log log = LogFactory.getLog(SessionHandler.class);
    private static SessionHandler sessionHandler;

    private Slot[] slotsWithTokens;
    private Module pkcs11Module;
    private ServerConfigurationService serverConfigurationService;
    private HashMap<Integer, String> configuredSlots;

    protected SessionHandler(ServerConfigurationService serverConfigurationService) throws CryptoException {

        String pkcs11ModulePath = serverConfigurationService.getFirstProperty(PKCS11_MODULE_PROPERTY_PATH);
        try {
            pkcs11Module = Module.getInstance(pkcs11ModulePath);
            pkcs11Module.initialize(null);
        } catch (IOException e) {
            String errorMessage = String.format("Unable to locate PKCS #11 Module in path '%s'.", pkcs11ModulePath);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new CryptoException(errorMessage, e);
        } catch (TokenException e) {
            String errorMessage = "PKCS #11 Module initialization failed.";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new HSMCryptoException(errorMessage, e);
        }
        this.serverConfigurationService = serverConfigurationService;
        configuredSlots = new HashMap<Integer, String>();
        setupSlotConfiguration();
    }

    /**
     * Singleton design pattern is used.
     *
     * @param serverConfigurationService
     * @return Default instance of SessionHandler.
     * @throws CryptoException
     */
    public static SessionHandler getDefaultSessionHandler(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        synchronized (SessionHandler.class) {
            if (sessionHandler == null) {
                sessionHandler = new SessionHandler(serverConfigurationService);
            }
        }
        return sessionHandler;
    }

    /**
     * Initiate a session for a given slot.
     *
     * @param slotNo : Slot number of the required session
     * @return Instance of a Session.
     * @throws CryptoException
     */
    public Session initiateSession(int slotNo, boolean readWriteSession) throws CryptoException {

        if (slotsWithTokens == null) {
            try {
                slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
            } catch (TokenException e) {
                String errorMessage = String.format("Failed to retrieve slots with tokens.");
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        }
        if (slotsWithTokens.length > slotNo) {
            Slot slot = slotsWithTokens[slotNo];
            try {
                Token token = slot.getToken();
                Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
                        readWriteSession, null, null);
                session.login(Session.UserType.USER, getUserPIN(slotNo));
                return session;
            } catch (TokenException e) {
                String errorMessage = String.format("Session initiation failed for slot id : '%d' ", slotNo);
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        } else {
            String errorMessage = String.format("Slot '%d' is not configured for cryptographic operations.", slotNo);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }

    /**
     * Close the given session.
     *
     * @param session : Session that need to be closed.
     * @throws CryptoException
     */
    public void closeSession(Session session) throws CryptoException {

        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException e) {
                String errorMessage = "Error occurred during session termination.";
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new HSMCryptoException(errorMessage, e);
            }
        }
    }

    protected char[] getUserPIN(int slotID) throws CryptoException {

        if (configuredSlots.containsKey(slotID)) {
            return configuredSlots.get(slotID).toCharArray();
        } else {
            String errorMessage = String.format("Unable to retrieve slot configuration information for slot id " +
                    "'%d'.", slotID);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }

    protected void setupSlotConfiguration() throws CryptoException {

        NodeList configuredSlotsCandidateNodes = this.serverConfigurationService.getDocumentElement().
                getElementsByTagName("SlotConfiguration");
        if (configuredSlotsCandidateNodes != null) {
            Node hsmSlotConfiguration = configuredSlotsCandidateNodes.item(0);
            NodeList configuredSlots = hsmSlotConfiguration.getChildNodes();
            for (int i = 0; i < configuredSlots.getLength(); i++) {
                Node configuredSlot = configuredSlots.item(i);
                if (configuredSlot.getNodeType() == Node.ELEMENT_NODE && "Slot".equals(configuredSlot.getNodeName())) {
                    NamedNodeMap attributes = configuredSlot.getAttributes();
                    int id = Integer.parseInt(attributes.getNamedItem("id").getTextContent());
                    String pin = attributes.getNamedItem("pin").getTextContent();
                    if (!this.configuredSlots.containsKey(id)) {
                        this.configuredSlots.put(id, pin);
                    }
                }
            }
        } else {
            String errorMessage = "Unable to retrieve slot configuration information.";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new CryptoException(errorMessage);
        }
    }
}
