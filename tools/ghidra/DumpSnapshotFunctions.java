// Decompile functions from a raw 32 MiB PP502x RAM snapshot in a read-only project.
// Import the extracted RAM with BinaryLoader at 0x10000000 and ARM:LE:32:v4t.
// Arguments are absolute runtime addresses, for example 0x10936ad0.
// @category iPodCrossfade

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DumpSnapshotFunctions extends GhidraScript {
    private static final long BASE = 0x10000000L;
    private static final long RAM_SIZE = 0x02000000L;

    @Override
    public void run() throws Exception {
        long memoryBase = currentProgram.getMemory().getMinAddress().getOffset();
        String language = currentProgram.getLanguageID().getIdAsString();
        println(String.format("RAM base: 0x%x; language: %s", memoryBase, language));
        if (memoryBase != BASE || !language.startsWith("ARM:LE:32:v4t")) {
            throw new IllegalStateException("Unexpected snapshot base or language");
        }

        String[] args = getScriptArgs();
        if (args.length == 0) {
            throw new IllegalArgumentException("Supply absolute runtime function addresses");
        }
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open Ghidra decompiler");
        }
        try {
            for (String value : args) {
                long absolute = Long.decode(value);
                if (absolute < BASE || absolute >= BASE + RAM_SIZE) {
                    throw new IllegalArgumentException("Address outside PP RAM: " + value);
                }
                Address address = toAddr(absolute);
                Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
                if (function == null) {
                    disassemble(address);
                    function = createFunction(address, null);
                }
                if (function == null) {
                    println(String.format("0x%x: no function could be defined", absolute));
                    continue;
                }
                println(String.format("=== RAM 0x%x (function %s) ===", absolute,
                        function.getEntryPoint()));
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    println("Decompiler failed: " + result.getErrorMessage());
                } else {
                    println(result.getDecompiledFunction().getC());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
