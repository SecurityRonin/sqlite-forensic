import fqlite.base.GUI;
import fqlite.base.Job;
import fqlite.base.Global;

import javafx.application.Platform;
import javafx.collections.ObservableList;

import java.io.File;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * HeadlessTap — a non-GUI oracle wrapper around fqlite's carving engine.
 *
 * <p>fqlite's CLI was removed at v2.0, but the carving engine ({@code fqlite.base.Job})
 * is plain Java that populates {@code Job.resultlist} — a
 * {@code ConcurrentHashMap<String, ObservableList<ObservableList<String>>>} keyed by
 * table name; the GUI merely reads it. This driver constructs {@code Job}, runs
 * {@code Job.run(path)} synchronously, and emits the recovered DELETED rows as CSV
 * ({@code rowid,col1,col2,...}) on stdout — never opening a JavaFX window.
 *
 * <p>Row layout in {@code resultlist} (verified against the engine source at the pinned
 * commit; see SETUP.md):
 * <pre>
 *   index 0 : table name (also the resultlist map key)
 *   index 1 : "[pll|headerlen]" payload-length info
 *   index 2 : rowid  ("-1" when the header rowid is unrecoverable)
 *   index 3 : status — Global.DELETED_RECORD_IN_PAGE ("D") = deleted,
 *                       Global.REGULAR_RECORD (" ") = live,
 *                       Global.FREELIST_ENTRY ("F") = freelist
 *   index 4 : physical byte offset
 *   index 5+: the actual table column values (col1, col2, ...)
 * </pre>
 *
 * <p>JavaFX coupling handled here: the engine's logger ({@code fqlite.log.AppLog}) has a
 * static initializer that builds a JavaFX {@code TextArea} and dereferences
 * {@code GUI.baseDir}. So before the first {@code Job} touches {@code AppLog}, the tap
 * (a) boots the JavaFX toolkit headlessly via {@code Platform.startup}, and (b) sets
 * {@code GUI.baseDir} to a writable temp dir. All {@code gui.*} calls inside
 * {@code Job.java} are already null-guarded, and {@code job.gui} is left null, so no
 * window is ever shown.
 */
public final class HeadlessTap {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: HeadlessTap <database.db>");
            System.exit(2);
        }
        String dbPath = args[0];
        File dbFile = new File(dbPath);
        if (!dbFile.isFile()) {
            System.err.println("HeadlessTap: not a file: " + dbPath);
            System.exit(2);
        }

        // (b) GUI.baseDir must be a writable, existing directory before AppLog's static
        // initializer runs (it opens <baseDir>/fqlite.log via a FileHandler).
        File baseDir = Files.createTempDirectory("fqlite-tap-").toFile();
        baseDir.deleteOnExit();
        GUI.baseDir = baseDir;

        // (c) Boot the JavaFX *toolkit* (no Stage, no window). AppLog's static block
        // constructs JavaFX controls, which requires the FX runtime to be started.
        CountDownLatch fxReady = new CountDownLatch(1);
        try {
            Platform.startup(fxReady::countDown);
        } catch (IllegalStateException already) {
            // Toolkit already initialized — fine.
            fxReady.countDown();
        }
        fxReady.await(30, TimeUnit.SECONDS);

        // The engine's info()/header dump goes to System.out when gui == null. Capture the
        // real stdout for our CSV, and silence the engine's chatter while it carves so only
        // the CSV reaches the caller's stdout.
        PrintStream realOut = System.out;
        PrintStream sink = new PrintStream(OutputStream.nullOutputStream());

        // Run the carving engine. Job.run(path) is synchronous: it reads the file,
        // schedules RecoveryTasks, waits for them, and returns with resultlist fully
        // populated. job.gui stays null -> no GUI is touched.
        Job job = new Job();
        job.setPath(dbFile.getAbsolutePath());
        System.setOut(sink);
        try {
            job.run(dbFile.getAbsolutePath());
        } finally {
            System.setOut(realOut);
        }

        emitDeletedRows(realOut, job.resultlist);

        // FX toolkit was started; exit explicitly so its daemon threads do not hang us.
        Platform.exit();
        System.exit(0);
    }

    /**
     * Drain resultlist and emit the recovered records the comparison harness consumes.
     *
     * <p>Output contract (matches forensic/tests/nemetz_tool_comparison.rs::fqlite_recover
     * and ::fqlite_schema_rereads): TWO leading metadata fields (rowid, offset) precede the
     * data columns, so the decoded tuple starts at CSV field index 2.
     *
     * <ul>
     *   <li><b>Deleted data record</b> → {@code rowid,offset,id,col1,col2,...}.
     *       The harness reads identity columns at fields 3 and 4 (= the row's col1,col2).</li>
     *   <li><b>Freed sqlite_master schema record</b> →
     *       {@code rowid,offset,id,rootpage,type,name,tbl_name,rootpage,sql}.
     *       The harness reads (type,name,tbl_name) at fields 4/5/6, and the data parser
     *       skips any line whose field 4 is one of table/index/trigger/view.</li>
     * </ul>
     */
    private static void emitDeletedRows(
            PrintStream out0,
            ConcurrentHashMap<String, ObservableList<ObservableList<String>>> resultlist) {

        StringBuilder out = new StringBuilder();
        Enumeration<String> tables = resultlist.keys();
        while (tables.hasMoreElements()) {
            String table = tables.nextElement();
            ObservableList<ObservableList<String>> rows = resultlist.get(table);
            if (rows == null) {
                continue;
            }
            for (ObservableList<String> row : rows) {
                if (isDeletedDataRow(row)) {
                    emitDataRow(out, row);
                } else if (isSchemaCarve(row)) {
                    emitSchemaRow(out, row);
                }
            }
        }
        out0.print(out);
        out0.flush();
    }

    /**
     * A recovered-DELETED *data* record: status cell (index 3) == Global.DELETED_RECORD_IN_PAGE
     * ("D"). Live rows carry Global.REGULAR_RECORD (" ") at index 3. Layout:
     * {@code [table, pll, rowid, "D", offset, id, col1, col2, ...]}.
     */
    private static boolean isDeletedDataRow(ObservableList<String> row) {
        return row != null && row.size() > 5
                && Global.DELETED_RECORD_IN_PAGE.equals(row.get(3))
                && hasDataColumnValue(row);
    }

    /**
     * A free-space over-read the engine still tags DELETED_RECORD_IN_PAGE carries a
     * rowid echo (and sometimes a zero id) but no legible column data — every field at or
     * after col1 (index 6) is empty, whitespace, or raw control bytes (e.g. {@code 0x10}
     * DLE the engine read from unallocated space). A recovered record must contain at
     * least one legible (printable, non-control, non-space) character; carves with none
     * are excluded so the oracle reports rows fqlite reconstructed, not the bytes around
     * them. The rule is general — it targets the absence of any legible glyph, not any
     * specific value or byte.
     */
    private static boolean hasDataColumnValue(ObservableList<String> row) {
        for (int i = 6; i < row.size(); i++) {
            String v = row.get(i);
            if (v == null) {
                continue;
            }
            for (int j = 0; j < v.length(); j++) {
                char c = v.charAt(j);
                if (!Character.isISOControl(c) && !Character.isWhitespace(c)
                        && !Character.isSpaceChar(c)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Emit a data row as {@code rowid,offset,id,col1,col2,...} (data tuple at field 2). */
    private static void emitDataRow(StringBuilder out, ObservableList<String> row) {
        out.append(csvField(nonEmptyRowid(row.get(2))));   // field 0: rowid
        out.append(',').append(csvField(row.get(4)));      // field 1: offset
        for (int i = 5; i < row.size(); i++) {             // fields 2+: id, col1, col2, ...
            out.append(',').append(csvField(row.get(i)));
        }
        out.append('\n');
    }

    /**
     * A freed sqlite_master schema carve. The engine stores these in the unmatched bucket
     * (map key "D") with cell 0 == "D" and a DIFFERENT layout — the sqlite_master columns
     * (type,name,tbl_name,rootpage,sql) sit at indices 4+:
     * {@code ["D", pll, rowid, offset, type, name, tbl_name, rootpage, sql]}. We recognise it
     * by cell 0 == "D" and a sqlite_master type token (table/index/trigger/view) at index 4.
     */
    private static boolean isSchemaCarve(ObservableList<String> row) {
        if (row == null || row.size() < 7
                || !Global.DELETED_RECORD_IN_PAGE.equals(row.get(0))) {
            return false;
        }
        String type = row.get(4);
        return "table".equals(type) || "index".equals(type)
                || "trigger".equals(type) || "view".equals(type);
    }

    /**
     * Emit a schema carve as {@code rowid,offset,id,rootpage,type,name,tbl_name,rootpage,sql}
     * so (type,name,tbl_name) land at CSV fields 4/5/6. Two filler metadata fields (id,
     * rootpage) precede the schema columns, matching fqlite's native schema-record shape and
     * the harness's documented contract. The harness only reads fields 4/5/6, so id is set to
     * the rowid and the rootpage column is reused for the unread filler slot.
     */
    private static void emitSchemaRow(StringBuilder out, ObservableList<String> row) {
        String rowid = nonEmptyRowid(row.get(2));
        String offset = row.get(3);
        String rootpage = (row.size() > 7) ? row.get(7) : "";
        out.append(csvField(rowid));         // field 0: rowid
        out.append(',').append(csvField(offset));    // field 1: offset
        out.append(',').append(csvField(rowid));     // field 2: id (filler)
        out.append(',').append(csvField(rootpage));  // field 3: rootpage (filler)
        for (int i = 4; i < row.size(); i++) {        // fields 4+: type,name,tbl_name,rootpage,sql
            out.append(',').append(csvField(row.get(i)));
        }
        out.append('\n');
    }

    private static String nonEmptyRowid(String rowid) {
        return (rowid == null || rowid.isEmpty()) ? "-1" : rowid;
    }

    /** Minimal RFC-4180-ish CSV quoting: quote when the field holds a comma, quote, or newline. */
    private static String csvField(String s) {
        if (s == null) {
            return "";
        }
        boolean needsQuote = s.indexOf(',') >= 0 || s.indexOf('"') >= 0
                || s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0;
        if (!needsQuote) {
            return s;
        }
        return '"' + s.replace("\"", "\"\"") + '"';
    }

    private HeadlessTap() {
    }
}
