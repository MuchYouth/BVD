// Dump function-level P-code and callsite evidence as JSONL.
//
// Headless usage:
//   analyzeHeadless <project_dir> <project_name> -import <binary> \
//     -scriptPath ghidra_scripts \
//     -postScript DumpPcodeJson.java <sample_id> <output_dir>

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DumpPcodeJson extends GhidraScript {
    private String sampleId;
    private String binaryName;
    private BufferedWriter pcodeWriter;
    private BufferedWriter callsiteWriter;
    private BufferedWriter errorWriter;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        sampleId = args.length > 0 && args[0] != null && !args[0].isEmpty()
            ? args[0]
            : safeString(currentProgram.getExecutableMD5());
        String outputDir = args.length > 1 && args[1] != null && !args[1].isEmpty()
            ? args[1]
            : ".";
        binaryName = currentProgram == null ? "" : safeString(currentProgram.getName());

        File dir = new File(outputDir);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new RuntimeException("Failed to create output directory: " + outputDir);
        }

        File pcodePath = new File(dir, sampleId + ".pcode.jsonl");
        File callsitePath = new File(dir, sampleId + ".callsites.jsonl");
        File errorPath = new File(dir, sampleId + ".ghidra_errors.jsonl");

        pcodeWriter = newWriter(pcodePath);
        callsiteWriter = newWriter(callsitePath);
        errorWriter = newWriter(errorPath);

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                dumpFunction(decompiler, function);
            }
        }
        finally {
            decompiler.dispose();
            closeQuietly(pcodeWriter);
            closeQuietly(callsiteWriter);
            closeQuietly(errorWriter);
        }
    }

    private void dumpFunction(DecompInterface decompiler, Function function) throws Exception {
        if (function == null) {
            return;
        }

        DecompileResults results = null;
        try {
            results = decompiler.decompileFunction(function, 60, monitor);
        }
        catch (Exception exc) {
            writeError(function, "decompile_exception", exc.toString());
            return;
        }

        if (results == null) {
            writeError(function, "decompile_no_results", "Decompiler returned null results");
            return;
        }
        if (!results.decompileCompleted()) {
            writeError(function, "decompile_failed", safeString(results.getErrorMessage()));
            return;
        }

        HighFunction highFunction = results.getHighFunction();
        if (highFunction == null) {
            writeError(function, "decompile_no_high_function", safeString(results.getErrorMessage()));
            return;
        }

        int opSeq = 0;
        for (java.util.Iterator<PcodeOpAST> it = highFunction.getPcodeOps(); it.hasNext();) {
            PcodeOpAST op = it.next();
            if (op == null) {
                continue;
            }
            writePcode(function, op, opSeq);
            if (isCallOp(op)) {
                writeCallsite(function, op);
            }
            opSeq += 1;
        }
    }

    private void writePcode(Function function, PcodeOpAST op, int opSeq) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        appendField(sb, "sample_id", sampleId).append(",");
        appendField(sb, "binary_name", binaryName).append(",");
        appendField(sb, "function_name", safeFunctionName(function)).append(",");
        appendField(sb, "function_entry", safeAddress(function == null ? null : function.getEntryPoint())).append(",");
        appendNumberField(sb, "op_seq", opSeq).append(",");
        appendField(sb, "op_address", safeOpAddress(op)).append(",");
        appendField(sb, "mnemonic", safeString(op.getMnemonic())).append(",");
        appendNumberField(sb, "opcode", op.getOpcode()).append(",");
        appendRawField(sb, "output_varnode", varnodeJson(op.getOutput())).append(",");
        appendRawField(sb, "input_varnodes", varnodeArrayJson(op)).append(",");
        appendField(sb, "basic_block", basicBlockString(op)).append(",");
        appendArrayField(sb, "warnings", new ArrayList<String>());
        sb.append("}");
        pcodeWriter.write(sb.toString());
        pcodeWriter.newLine();
    }

    private void writeCallsite(Function function, PcodeOpAST op) throws Exception {
        Varnode targetVarnode = op.getNumInputs() > 0 ? op.getInput(0) : null;
        Address targetAddress = targetVarnode == null ? null : targetVarnode.getAddress();
        Symbol targetSymbol = symbolAt(targetAddress);

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        appendField(sb, "sample_id", sampleId).append(",");
        appendField(sb, "binary_name", binaryName).append(",");
        appendField(sb, "function_name", safeFunctionName(function)).append(",");
        appendField(sb, "function_entry", safeAddress(function == null ? null : function.getEntryPoint())).append(",");
        appendField(sb, "call_address", safeOpAddress(op)).append(",");
        appendField(sb, "call_target_address", safeAddress(targetAddress)).append(",");
        appendField(sb, "call_target_name", targetSymbol == null ? "" : safeString(targetSymbol.getName(true))).append(",");
        appendBooleanField(sb, "is_external", isExternalTarget(targetAddress, targetSymbol)).append(",");
        appendRawField(sb, "raw_input_varnodes", varnodeArrayJson(op)).append(",");
        appendRawField(sb, "recovered_arguments", recoveredArgumentsJson(op)).append(",");
        appendField(sb, "argument_recovery_confidence", recoveredArgumentConfidence(op)).append(",");
        appendArrayField(sb, "warnings", callWarnings(op, targetSymbol));
        sb.append("}");
        callsiteWriter.write(sb.toString());
        callsiteWriter.newLine();
    }

    private void writeError(Function function, String errorType, String message) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        appendField(sb, "sample_id", sampleId).append(",");
        appendField(sb, "binary_name", binaryName).append(",");
        appendField(sb, "function_name", safeFunctionName(function)).append(",");
        appendField(sb, "function_entry", safeAddress(function == null ? null : function.getEntryPoint())).append(",");
        appendField(sb, "error_type", safeString(errorType)).append(",");
        appendField(sb, "message", safeString(message));
        sb.append("}");
        errorWriter.write(sb.toString());
        errorWriter.newLine();
    }

    private boolean isCallOp(PcodeOp op) {
        if (op == null) {
            return false;
        }
        int opcode = op.getOpcode();
        return opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND || opcode == PcodeOp.CALLOTHER;
    }

    private String varnodeArrayJson(PcodeOp op) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        if (op != null) {
            for (int i = 0; i < op.getNumInputs(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(varnodeJson(op.getInput(i)));
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String recoveredArgumentsJson(PcodeOp op) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        if (op != null) {
            boolean first = true;
            for (int i = 1; i < op.getNumInputs(); i++) {
                if (!first) {
                    sb.append(",");
                }
                sb.append("{");
                appendNumberField(sb, "index", i - 1).append(",");
                appendRawField(sb, "varnode", varnodeJson(op.getInput(i)));
                sb.append("}");
                first = false;
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String varnodeJson(Varnode varnode) {
        if (varnode == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        appendField(sb, "space", varnode.getAddress() == null ? "" : safeString(varnode.getAddress().getAddressSpace().getName())).append(",");
        appendField(sb, "address", safeAddress(varnode.getAddress())).append(",");
        appendNumberField(sb, "offset", varnode.getOffset()).append(",");
        appendNumberField(sb, "size", varnode.getSize()).append(",");
        appendBooleanField(sb, "is_constant", varnode.isConstant()).append(",");
        appendBooleanField(sb, "is_unique", varnode.isUnique()).append(",");
        appendBooleanField(sb, "is_register", varnode.isRegister()).append(",");
        appendBooleanField(sb, "is_address", varnode.isAddress()).append(",");
        appendBooleanField(sb, "is_addr_tied", varnode.isAddrTied());
        sb.append("}");
        return sb.toString();
    }

    private String basicBlockString(PcodeOpAST op) {
        try {
            PcodeBlockBasic parent = op == null ? null : op.getParent();
            if (parent == null) {
                return "";
            }
            return safeString(parent.toString());
        }
        catch (Exception exc) {
            return "";
        }
    }

    private String safeOpAddress(PcodeOpAST op) {
        try {
            SequenceNumber seq = op == null ? null : op.getSeqnum();
            return seq == null ? "" : safeAddress(seq.getTarget());
        }
        catch (Exception exc) {
            return "";
        }
    }

    private Symbol symbolAt(Address address) {
        try {
            if (address == null || currentProgram == null) {
                return null;
            }
            SymbolTable table = currentProgram.getSymbolTable();
            return table == null ? null : table.getPrimarySymbol(address);
        }
        catch (Exception exc) {
            return null;
        }
    }

    private boolean isExternalTarget(Address address, Symbol symbol) {
        try {
            if (symbol != null && symbol.isExternal()) {
                return true;
            }
            if (address == null || currentProgram == null) {
                return false;
            }
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(address);
            while (refs != null && refs.hasNext()) {
                Reference ref = refs.next();
                if (ref != null && ref.isExternalReference()) {
                    return true;
                }
            }
        }
        catch (Exception exc) {
            return false;
        }
        return false;
    }

    private String recoveredArgumentConfidence(PcodeOp op) {
        if (op == null || op.getNumInputs() <= 1) {
            return "unknown";
        }
        return "raw_pcode_inputs";
    }

    private List<String> callWarnings(PcodeOp op, Symbol targetSymbol) {
        List<String> warnings = new ArrayList<String>();
        if (op == null || op.getNumInputs() == 0) {
            warnings.add("missing_raw_call_inputs");
        }
        if (targetSymbol == null) {
            warnings.add("unresolved_call_target_name");
        }
        if (op == null || op.getNumInputs() <= 1) {
            warnings.add("no_recovered_arguments");
        }
        return warnings;
    }

    private BufferedWriter newWriter(File path) throws Exception {
        return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(path), StandardCharsets.UTF_8));
    }

    private void closeQuietly(BufferedWriter writer) {
        try {
            if (writer != null) {
                writer.close();
            }
        }
        catch (Exception exc) {
            // Ignore close errors in headless extraction cleanup.
        }
    }

    private String safeFunctionName(Function function) {
        try {
            return function == null ? "" : safeString(function.getName(true));
        }
        catch (Exception exc) {
            return "";
        }
    }

    private String safeAddress(Address address) {
        return address == null ? "" : safeString(address.toString());
    }

    private String safeString(Object value) {
        return value == null ? "" : value.toString();
    }

    private StringBuilder appendField(StringBuilder sb, String name, String value) {
        appendJsonString(sb, name);
        sb.append(":");
        appendJsonString(sb, value);
        return sb;
    }

    private StringBuilder appendNumberField(StringBuilder sb, String name, long value) {
        appendJsonString(sb, name);
        sb.append(":").append(value);
        return sb;
    }

    private StringBuilder appendBooleanField(StringBuilder sb, String name, boolean value) {
        appendJsonString(sb, name);
        sb.append(":").append(value ? "true" : "false");
        return sb;
    }

    private StringBuilder appendRawField(StringBuilder sb, String name, String jsonValue) {
        appendJsonString(sb, name);
        sb.append(":").append(jsonValue == null ? "null" : jsonValue);
        return sb;
    }

    private StringBuilder appendArrayField(StringBuilder sb, String name, List<String> values) {
        appendJsonString(sb, name);
        sb.append(":[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(",");
            }
            appendJsonString(sb, values.get(i));
        }
        sb.append("]");
        return sb;
    }

    private void appendJsonString(StringBuilder sb, String value) {
        sb.append("\"");
        if (value != null) {
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '"':
                        sb.append("\\\"");
                        break;
                    case '\\':
                        sb.append("\\\\");
                        break;
                    case '\b':
                        sb.append("\\b");
                        break;
                    case '\f':
                        sb.append("\\f");
                        break;
                    case '\n':
                        sb.append("\\n");
                        break;
                    case '\r':
                        sb.append("\\r");
                        break;
                    case '\t':
                        sb.append("\\t");
                        break;
                    default:
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        }
                        else {
                            sb.append(c);
                        }
                        break;
                }
            }
        }
        sb.append("\"");
    }
}
