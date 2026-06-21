package fqlite.rag;

import javafx.stage.Stage;

/**
 * Compile-only stub for the headless fqlite tap (see {@link LLMWindow}).
 * Referenced only by GUI.java's {@code prepareLLM(...)}, never reached headlessly.
 */
public class LoadingPopup {

    public void show(Stage owner, String message) {
        throw new UnsupportedOperationException("fqlite.rag stubbed out in headless tap");
    }

    public void close() {
        throw new UnsupportedOperationException("fqlite.rag stubbed out in headless tap");
    }
}
