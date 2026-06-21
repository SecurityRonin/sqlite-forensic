package fqlite.rag;

import fqlite.base.GUI;
import fqlite.ui.NodeObject;
import javafx.application.Application;
import javafx.scene.control.TreeItem;
import javafx.stage.Stage;

/**
 * Compile-only stub for the headless fqlite tap.
 *
 * <p>The real {@code fqlite.rag.LLMWindow} drives a langchain4j / llama.cpp
 * (de.kherud.llama) RAG agent and is referenced ONLY by {@code GUI.java}, which
 * the headless carving path never instantiates. Replacing the langchain4j-heavy
 * package with this stub lets the engine + GUI compile without the LLM deps.
 * The methods below are never invoked headlessly; they exist only to satisfy
 * GUI.java's call sites at compile time.
 */
public class LLMWindow extends Application {

    public LLMWindow(GUI parent, TreeItem<NodeObject> node) {
        throw new UnsupportedOperationException("fqlite.rag stubbed out in headless tap");
    }

    public Stage getPrimaryStage() {
        throw new UnsupportedOperationException("fqlite.rag stubbed out in headless tap");
    }

    @Override
    public void start(Stage primaryStage) {
        throw new UnsupportedOperationException("fqlite.rag stubbed out in headless tap");
    }

    public void prepareRAG(String model_path) {
        throw new UnsupportedOperationException("fqlite.rag stubbed out in headless tap");
    }

    public void show() {
        throw new UnsupportedOperationException("fqlite.rag stubbed out in headless tap");
    }
}
