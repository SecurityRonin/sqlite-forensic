package fqlite.erm;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Compile-only stub for the headless fqlite tap.
 *
 * <p>The real {@code fqlite.erm.SchemaRetriever} builds a langchain4j embedding
 * store; it is referenced ONLY by {@code GUI.java}'s ER-diagram export, never on
 * the headless carving path. This stub satisfies the GUI compile without the
 * langchain4j dependency.
 */
public class SchemaRetriever {

    public SchemaRetriever(Connection connection) {
        throw new UnsupportedOperationException("fqlite.erm stubbed out in headless tap");
    }

    public String extractFullSchema(Connection dbConnection) throws SQLException {
        throw new UnsupportedOperationException("fqlite.erm stubbed out in headless tap");
    }
}
