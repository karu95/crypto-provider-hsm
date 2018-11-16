package org.wso2.carbon.crypto.provider.hsm;

/**
 * An instance of this class holds slot ID and PIN of HSM device's slot.
 */
public class SlotInfo {

    private int slotID;
    private String pin;

    /**
     * Constructor of {@link SlotInfo}.
     *
     * @param slotID : ID of a given slot.
     * @param pin    : User PIN of the slot related to above slot ID.
     */
    public SlotInfo(int slotID, String pin) {

        this.slotID = slotID;
        this.pin = pin;
    }

    public int getSlotID() {

        return slotID;
    }

    public String getPin() {

        return pin;
    }
}
