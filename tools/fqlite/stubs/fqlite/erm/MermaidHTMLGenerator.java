package fqlite.erm;

import java.io.IOException;

/**
 * Compile-only stub for the headless fqlite tap (see {@link SchemaRetriever}).
 * Referenced only by GUI.java's ER-diagram export, never reached headlessly.
 */
public class MermaidHTMLGenerator {

    public static void setMermaidLibraryPath(String path) {
        throw new UnsupportedOperationException("fqlite.erm stubbed out in headless tap");
    }

    public static void setPanzoomLibraryPath(String path) {
        throw new UnsupportedOperationException("fqlite.erm stubbed out in headless tap");
    }

    public static void generateHTMLFile(String mermaidCode, String outputPath) throws IOException {
        throw new UnsupportedOperationException("fqlite.erm stubbed out in headless tap");
    }
}
