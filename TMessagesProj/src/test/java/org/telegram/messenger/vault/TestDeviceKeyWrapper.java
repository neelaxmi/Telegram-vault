package org.telegram.messenger.vault;

/**
 * Test double for the Android Keystore layer: real AES-256-GCM under a random in-memory key,
 * so tampering is detected exactly as with the production wrapper. Can be told to behave as
 * if the device key had been lost.
 */
class TestDeviceKeyWrapper implements DeviceKeyWrapper {

    private static final byte[] AAD = {'d', 'e', 'v'};

    private byte[] key = VaultCrypto.randomBytes(VaultCrypto.KEY_BYTES);
    boolean keyAvailable = true;
    int deleteCalls;
    boolean failDelete;

    @Override
    public byte[] wrap(byte[] data) throws VaultCryptoException {
        requireKey();
        return VaultCrypto.encrypt(key, data, AAD);
    }

    @Override
    public byte[] unwrap(byte[] wrapped) throws VaultCryptoException {
        requireKey();
        return VaultCrypto.decrypt(key, wrapped, AAD);
    }

    @Override
    public void deleteKey() throws VaultCryptoException {
        deleteCalls++;
        if (failDelete) {
            throw new VaultCryptoException(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, "delete failed");
        }
        key = null;
        keyAvailable = false;
    }

    private void requireKey() throws VaultCryptoException {
        if (!keyAvailable || key == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, "device key gone");
        }
    }
}
