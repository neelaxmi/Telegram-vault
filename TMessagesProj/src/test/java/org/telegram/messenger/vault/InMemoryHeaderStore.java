package org.telegram.messenger.vault;

import java.io.IOException;

/** Test double for {@link VaultHeaderStore} with switchable failures. */
class InMemoryHeaderStore implements VaultHeaderStore {

    byte[] data;
    boolean failWrites;
    boolean failReads;
    boolean failDeletes;

    @Override
    public boolean exists() {
        return data != null;
    }

    @Override
    public byte[] read() throws IOException {
        if (failReads || data == null) {
            throw new IOException("read failed");
        }
        return data.clone();
    }

    @Override
    public void write(byte[] bytes) throws IOException {
        if (failWrites) {
            throw new IOException("write failed");
        }
        data = bytes.clone();
    }

    @Override
    public void delete() throws IOException {
        if (failDeletes) {
            throw new IOException("delete failed");
        }
        data = null;
    }
}
