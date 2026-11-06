package org.telegram.messenger.vault;

import java.io.IOException;

/** Persistence for the single, small, wrapped vault key header. */
public interface VaultHeaderStore {

    boolean exists();

    /** @throws IOException if missing or unreadable */
    byte[] read() throws IOException;

    /** Replaces the stored header atomically: readers see the old or the new value, never a partial one. */
    void write(byte[] data) throws IOException;

    /** Removes the header. Without it the vault data key is gone and all vault data is unrecoverable. */
    void delete() throws IOException;
}
