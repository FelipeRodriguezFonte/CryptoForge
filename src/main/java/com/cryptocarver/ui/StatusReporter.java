package com.cryptocarver.ui;

/**
 * Interface for controllers that can report status and show errors.
 * Bridging MainController (Lead/Legacy) and ModernMainController.
 */
public interface StatusReporter {
    void updateStatus(String message);

    void updateInspector(String operation, byte[] input, byte[] output, java.util.Map<String, String> details);

    void showError(String title, String message);

    default void addToHistory(String operation, java.util.Map<String, String> details) {
        // Default implementation does nothing, for legacy compatibility
    }
}
